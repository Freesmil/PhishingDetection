#!/usr/bin/env python

import ipaddress
import multiprocessing
import os
import psycopg2
import re
import subprocess
import sys
import time
import urllib
import yara
from bs4 import BeautifulSoup
from multiprocessing import Value
from pylibs.urlnorm.urlnorm_ext import get_first_level_domain
from pylibs.urlnorm.urlnorm_ext import get_hostname
from termcolor import cprint
from urllib.parse import urlparse


class Database:
    """
    Class Database is for manipulation with the database
    """

    def __init__(self):
        """
        Class constructor.
        
        """

        try:
            self.conn = psycopg2.connect("dbname='phishing' user='admin' host='localhost' password='admin'")
        except psycopg2.Error:
            cprint("DATABASE ERROR: Unable to connect to the database", 'red')

    def is_domain_in_blacklist(self, domain):
        """
        Checks if domain is in the DB blacklist. If yes returns true else false
        
        :param str domain: name of domain/link
        :return: True if the domain is in the DB or False if not
        :rtype: bool
        """
        try:
            converted = get_first_level_domain(domain)
            urls = (converted, domain)
        except TypeError:
            return False

        cur = self.conn.cursor()

        try:
            cur.execute("""SELECT domain FROM blacklist WHERE domain IN %s""", (urls,))
        except psycopg2.DatabaseError:
            cprint("DATABASE ERROR: Execution of SELECT failed", 'red')

        try:
            result = cur.fetchall()
        except psycopg2.ProgrammingError:
            return False

        if not result:
            return False

        return True


class Parser:
    """
    Class Parser is for parsing all needed parameters and elements from HTML code
    """

    def __init__(self):
        """
        Constructor.  
        """

    def parse(self, domain, html_before, html_after):
        """
        Parse all needed parts and return in dict
        :param str domain: name of domain 
        :param str html_before: HTML before JS execution
        :param str html_after:  HTML after JS execution
        :return: Needed parsed elements and parameters for further detection
        :rtype: dict
        """

        links = self.get_links(domain, html_after)

        result = {'domain': domain,
                  'html': html_after,
                  'links': links,
                  'links_outside': self.get_outside_links(domain, links)}

        return result


    def get_links(self, domain, html):
        """
        Gets html DOM and returns links from elements 'a' and 'link' in 'body'.
        :param domain: 
        :param str html: DOM 
        :return: All links within DOM
        :rtype: set
        """

        links = set()

        for a in html('a'):
            try:
                link = urllib.parse.unquote(urllib.parse.unquote(a['href']))
                links.add(link)
            except KeyError:
                continue

        try:
            for a in html('link'):
                try:
                    link = urllib.parse.unquote(urllib.parse.unquote(a['href']))
                    links.add(link)
                except KeyError:
                    continue
        except:
            cprint("INFO: Domain " + domain + " has no body element", 'cyan')
            return set()

        new_links = set()

        for link in links:
            try:
                if link.index('@') > 0:
                    position = link.index('@')
                    new_links.add(link[:position])
                    new_links.add(link[position+1:])
            except ValueError:
                continue

        links = links | new_links

        return links

    def get_outside_links(self, domain, links):
        """
        Gets links and return which are outside of the domain.
        :param str domain: name of domain 
        :param set links: set of links within DOM 
        :return: Links which are outside of the domain
        :rtype: set
        """

        outside_links = set()

        for link in links:
            if (link.find("http://") == 0 or link.find("https://") == 0) \
                    and (get_first_level_domain(link) != domain):
                outside_links.add(link)

        return outside_links


class Detector:
    """
    Class for detection malicious content within code of the website
    """

    def __init__(self):
        """
        Constructor.
        
        """
        self.database = Database()

        self.yara_matches = 0
        self.yara_rules = yara.compile(
            filepath = os.path.dirname(os.path.realpath(__file__))+'/'+'patterns.yar'
        )

    def detection(self, parsed_domain):
        """
        Main function for summary all results of detection
        :param dict parsed_domain: Domain with parsed information 
        :return: Results of all types of detection
        :rtype: dict
        """
        links = parsed_domain['links']

        result = {'name': parsed_domain['domain']}
        result['domain'] = self.link_detection(parsed_domain['domain'], True)
        result['html'] = {}
        result['html']['links'] = {}
        result['html']['links_outside_count'] = len(parsed_domain['links_outside'])
        result['html']['links_count'] = len(parsed_domain['links'])

        result['html']['code_xss'] = self.code_xss(parsed_domain['html'])

        result['html']['redirects'] = self.redirects_detection(parsed_domain['html'], parsed_domain['domain'])

        self.yara_detection(parsed_domain['html'])
        result['html']['yara'] = self.yara_matches

        for link in links:
            result['html']['links'][link] = self.link_detection(link)

        return result

    def link_detection(self, link):
        """
        Gets a link and detect all what can a link hide
        :param str link: URL 
        :return: All results of link detection 
        :rtype: dict
        """
        result =  {'name': link}
        result['blacklist'] = self.database.is_domain_in_blacklist(link)
        result['count_subdomains'] = self.link_count_subdomains(link)
        result['ip'] = self.link_is_ip_address(link)
        result['xss'] = self.is_link_xss(link)
        result['man'] = self.link_manipulation(link)

        return result

    def link_is_ip_address(self, link):
        """
        If link is IP address returns True else False
        :param str link: URL 
        :return: If link is IP address returns True else False
        :rtype: bool
        """
        try:
            link = get_first_level_domain(link)
        except TypeError:
            return False

        try:
            ipaddress.ip_address(link)
            return True
        except ValueError:
            return False

    def link_manipulation(self, link):
        """
        Tests if a link has any phishing pattern
        :param str link: URL 
        :return: If link has phishing pattern
        :rtype: bool
        """
        patterns = {
            "([a-z]+\.)?[a-z]+-with-[a-z]+\.us",
            "[a-z0-9]{3}zz\.[a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]{3,}",
            "^[a-z]{3,}-([0-9]{2}[a-z]{,3}|[a-z]{,3}[0-9]{2}).win$",
            '^email\.[a-z0-9]+\.at\.gmail\.com\.[a-z0-9]+\.(space|club)$',
            '^security-alert\..*\.(bid)$',
            '^h[a-z0-9]{3}\.(website|site|online)$',
            '^[a-z]+[0-9]{4}\.[a-z0-9]+\.xyz$',
            '\.com-.*',
            'inbox-msg-.*\.(gdn|top)$',
            '.*chrome.*\.ru',
            '.*dating.*\.(top|bid|accountant)$',
            'hotgirls\..*\.xyz'
        }

        for pattern in patterns:
            regex = re.compile(pattern)
            result = regex.match(link)

            if result:
                return True

            return False

    def link_count_subdomains(self, link):
        """
        Counts how many has got link subdomains 
        :param str link: URL 
        :return: If link has 5 and more subdomains return True else False
        :rtype: bool
        """
        count = 0

        hostname = get_hostname(link)
        try:
            count = hostname.replace(get_first_level_domain(hostname), '').count('.')
        except:
            return False

        if count > 4:
            return True

        return False

    def is_link_xss(self, link):
        """
        Check if link contains XSS
        :param str link: URL 
        :return: If link is XSS
        :rtype: bool
        """
        try:
            link = urlparse(link)
            query = link.query
        except TypeError:
            return False

        xss_patterns = {
            '<script>',
            'onclick=',
            'ondblclick=',
            'onmousedown=',
            'onmouseup=',
            'onmouseover=',
            'onmousemove=',
            'onmouseout=',
            'ondragstart=',
            'ondrag=',
            'ondragenter=',
            'ondragleave=',
            'ondragover=',
            'ondrop=',
            'ondragend=',
            'onkeydown=',
            'onkeypress=',
            'onkeyup=',
            'onload=',
            'onunload=',
            'onabort=',
            'onerror=',
            'onresize=',
            'onscroll=',
            'onselect=',
            'onchange=',
            'onsubmit=',
            'onreset=',
            'onfocus=',
            'onblur=',
            'onpointerdown=',
            'onpointerup=',
            'onpointercancel=',
            'onpointermove=',
            'onpointerover=',
            'onpointerout=',
            'onpointerenter=',
            'onpointerleave=',
            'ongotpointercapture=',
            'onlostpointercapture=',
            'oncut=',
            'oncopy=',
            'onpaste=',
            'onbeforecut=',
            'onbeforecopy=',
            'onbeforepaste=',
            'onafterupdate=',
            'onbeforeupdate=',
            'oncellchange=',
            'ondataavailable=',
            'ondatasetchanged=',
            'ondatasetcomplete=',
            'onerrorupdate=',
            'onrowenter=',
            'onrowexit=',
            'onrowsdelete=',
            'onrowinserted=',
            'oncontextmenu=',
            'ondrag=',
            'ondragstart=',
            'ondragenter=',
            'ondragover=',
            'ondragleave=',
            'ondragend=',
            'ondrop=',
            'onselectstart=',
            'onhelp=',
            'onbeforeunload=',
            'onstop=',
            'onbeforeeditfocus=',
            'onstart=',
            'onfinish=',
            'onbounce=',
            'onbeforeprint=',
            'onafterprint=',
            'onpropertychange=',
            'onfilterchange=',
            'onreadystatechange=',
            'onlosecapture=',
            'DOMMouseScroll=',
            'ondragdrop=',
            'ondragenter=',
            'ondragexit=',
            'ondraggesture=',
            'ondragover=',
            'onclose=',
            'oncommand=',
            'oninput=',
            'DOMMenuItemActive=',
            'DOMMenuItemInactive=',
            'oncontextmenu=',
            'onoverflow=',
            'onoverflowchanged=',
            'onunderflow=',
            'onpopuphidden=',
            'onpopuphiding=',
            'onpopupshowing=',
            'onpopupshown=',
            'onbroadcast=',
            'oncommandupdate=',
            'eventTypeArg=',
            'canBubbleArg=',
            'cancelableArg'
        }

        for pattern in xss_patterns:
            if query.find(pattern) != -1:
                return True

        return False

    def redirects_detection(self, code, domain):
        """
        Detects if a code contains redirects
        :param str code: DOM 
        :param str domain: name of domain 
        :return: Contained redirects
        :rtype: dict
        """
        redirects = dict()
        redirects['outside'] = self.redirects_html(code, domain)

        return redirects

    def redirects_html(self, code, domain):
        """
        Gets a code and detect there redirect patterns
        :param str code: HTML 
        :param str domain: name of domain 
        :return: Number of redirects
        :rtype: int
        """

        count = 0
        links = set()

        for meta in code('meta'):
            try:
                if(meta['http-equiv'] == "refresh" or meta['http-equiv'] == "location"):
                    content = meta['content']
                    link = content[(meta['content'].find("url=")+4):]
                    links.add(link)
            except KeyError:
                continue

        for iframe in code('iframe'):
            try:
                link = iframe['src']
            except KeyError:
                continue

        for base in code('base'):
            try:
                link = base['href']
            except KeyError:
                continue

        for link in links:
            if (link.find("http://") == 0 or link.find("https://") == 0) \
                    and (get_first_level_domain(link) != domain):
                count = count + 1

        for form in code('form'):
            try:
                link = form['action']
            except KeyError:
                continue

        return count

    def yara_detection(self, code):
        """
        Detection of occurrence of malware pattern
        :param code: 
        :return: If code contains yara pattern
        :rtype: bool
        """
        self.yara_matches = 0

        try:
            matches = self.yara_rules.match(data=code.prettify())
            self.yara_matches += len(matches)
        except TypeError:
            cprint("YARA error occurred while matching rules.", "red")
            return False
        except yara.SyntaxError:
            cprint("YARA error occurred while matching rules.", "red")
            return False

        return True

    def code_xss(self, code):
        """
        Detection if Javascript contains XSS by pytterns
        :param str code: DOM
        :return: If code has XSS
        :rtype: bool
        """
        patterns = {
            "document.write('<script",
            'document.write("<script',
            ').append("<script',
            ").append('<script"
        }
        code = code.prettify()

        for pattern in patterns:
            if code.find(pattern) != -1:
                return True

        return False


class Evaluation:
    """
    Class for evaluating results from Detection
    """

    def __init__(self, count):
        """
        Constructor.
        :param int count: index of searched website 
        """
        self.count = count
        self.dangerous = 0
        self.safe = 0
        self.suspicisous = 0
        self.yara = 0
        self.redirects = 0
        self.blacklist = 0
        self.xss = 0
        self.link_manipulation = 0

    def evaluate(self, detection_result, index):
        """
        The summary of evaluation of the website
        :param dict detection_result: given results from Detection 
        :param int index: index of searched website 
        """

        links = detection_result['html']['links']

        result = detection_result

        result['html']['links'] = {'blacklist': 0,
                                   'ip': 0,
                                   'count_subdomains': 0,
                                   'xss': 0,
                                   'man': 0
                                   }

        for link in links.values():
            if(link['blacklist'] is True):
                result['html']['links']['blacklist'] += 1
            if (link['ip'] is True):
                result['html']['links']['ip'] += 1
            if (link['count_subdomains'] is True):
                result['html']['links']['count_subdomains'] += 1
            if (link['xss'] is True):
                result['html']['links']['xss'] += 1
            if (link['man'] is True) or (result['domain']['man'] is True):
                result['html']['links']['man'] +=1

        status = "safe"

        if((result['domain']['blacklist'] is True) or (result['domain']['xss'] is True) or (result['html']['yara'] > 0) \
               or (result['html']['links']['xss'] > 0) or (result['html']['links']['blacklist'] > 0) or (result['html']['code_xss'])):
            status = "dangerous"
        elif((result['html']['links']['ip'] > 0) or (result['html']['links']['count_subdomains'] > 0) \
                or (result['domain']['ip'] is True) or (result['html']['redirects']['outside'] > 0) \
                or (result['html']['links']['man'] is True) or (result['domain']['count_subdomains'] is True)):
            status = "suspicious"

        result['domain']['status'] = status

        self.print(result)

        self.count_total(result)

        self.print_total(index)

    def count_total(self, result):
        """
        Counting the main summary of all websites
        :param dict result: results of Detection of website 
        """
        if(result['domain']['status'] == 'dangerous'):
            total_dangerous.value += 1
        if(result['domain']['status'] == 'suspicious'):
            total_suspicious.value += 1
        if(result['domain']['status'] == 'safe'):
            total_safe.value += 1

        if((result['domain']['xss'] is True) or (result['html']['code_xss'] is True)):
            total_xss.value += 1
        if(result['domain']['blacklist'] is True):
            total_blacklist.value += 1
        if(result['html']['redirects'] is True):
            total_redirects.value += 1
        if(result['html']['yara'] > 0):
            total_yara.value += 1

        if((result['html']['links']['blacklist'] > 0)):
            total_links_blacklist.value += 1

        if ((result['html']['links']['xss'] > 0)):
            total_links_xss.value += 1

        if ((result['html']['links']['ip'] > 0)
            or (result['html']['links']['count_subdomains'] > 0)
            or (result['html']['links']['man'] > 0)):
            total_link_manipulation.value += 1

    def print(self, result):
        """
        Prints results of all detection types of website        
        :param dict result: Results of website detection 
        """
        cprint(" --- ", "grey")
        cprint("Domain: " + result['name'], 'cyan')
        cprint("    Domain is " + result['domain']['status'])
        cprint("    Blacklist: " + str(result['domain']['blacklist']), 'white')
        cprint("    IP: " + str(result['domain']['ip']), 'white')
        cprint("    XSS: " + str(result['domain']['xss'] | result['html']['code_xss']), 'white')
        cprint("    Too many subdomains: " + str(result['domain']['count_subdomains']), 'white')
        cprint("    Outside redirects: " + str(result['html']['redirects']['outside']), 'white')
        cprint("    Found malware pattern: " + str(result['html']['yara']), 'white')
        cprint("    Links: ", 'white')
        cprint("        Count: " + str(result['html']['links_count']), 'white')
        cprint("        Outside count: " + str(result['html']['links_outside_count']), 'white')
        cprint("        Blacklist: " + str(result['html']['links']['blacklist']), 'white')
        cprint("        IP: " + str(result['html']['links']['ip']), 'white')
        cprint("        XSS: " + str(result['html']['links']['xss']), 'white')
        cprint("        Too many subdomains: " + str(result['html']['links']['count_subdomains']), 'white')

    def print_total(self, index):
        """
        Prints summary of all websites
        :param int index: index of last detected website 
        """
        cprint(" --- ", "grey")
        cprint(str(index) + "/" + str(self.count) + " are processed")
        cprint("Dangerous domains: " + str(total_dangerous.value), "white")
        cprint("Suspicious domains: " + str(total_suspicious.value), "white")
        cprint("Safe domains: " + str(total_safe.value), "white")

        cprint("XSS: " + str(total_xss.value), "white")
        cprint("Blacklist: " + str(total_blacklist.value), "white")
        cprint("Redirect: " + str(total_redirects.value), "white")
        cprint("Found malware patters: " + str(total_yara.value), "white")
        cprint("Link manipulation: " + str(total_link_manipulation.value), "white")
        cprint("Links blacklist: " + str(total_links_blacklist.value), "white")
        cprint("Links XSS: " + str(total_links_xss.value), "white")


def detect_website(data):
    """
    The main function for downloading website which are then send to Parser, Detector and Evaluator
    :param set data: data with index of the domain and its name  
    """
    index = data[0]
    domain = data[1]

    bash_command_before_js = 'wget -qO- -t 1 --connect-timeout=5 http://' + domain
    bash_command_after_js = 'google-chrome-stable --headless --timeout=5000 --virtual-time-budget=5000 --disable-gpu' \
                            ' --dump-dom http://' + domain #+ '2> /dev/null'


    try:
        output_before_js = subprocess.check_output(['bash', '-c', bash_command_before_js], timeout=15)
    except subprocess.CalledProcessError:
        cprint("WARNING: Something has gone wrong with executing wget, domain: " + domain, 'red')
        return
    except subprocess.TimeoutExpired:
        cprint("WARNING: Something has gone wrong with executing wget (timeout expired), domain: " + domain, 'red')
        return

    try:
        output_after_js = subprocess.check_output(['bash', '-c', bash_command_after_js], timeout=15)
    except subprocess.CalledProcessError:
        cprint("WARNING: Something has gone wrong with executing Chrome, domain: " + domain, 'red')
        return
    except subprocess.TimeoutExpired:
        cprint("WARNING: Something has gone wrong with executing Chrome (timeout expired), domain: " + domain, 'red')
        return

    html_before_js = BeautifulSoup(output_before_js, 'html.parser')
    html_after_js = BeautifulSoup(output_after_js, 'html.parser')

    try:
        html_before_js.prettify()
        html_after_js.prettify()
    except Exception:
        return

    if html_before_js is None:
        cprint("WARNING: Wget returned an empty web page, domain: " + domain, 'red')
        return

    if html_after_js is None:
        cprint("WARNING: Chrome returned an empty web page, domain: " + domain, 'red')
        return

    try:
        parsed_domain = parser.parse(domain, html_before_js, html_after_js)

        detection_result = detector.detection(parsed_domain)

        evaluator.evaluate(detection_result, index)
    except Exception:
        return


if __name__ == "__main__" :
    start_program_time = time.time()
    domain_file = sys.argv[1]

    with open(domain_file, 'r') as input_file:
        domains = input_file.readlines()

    domains = [domain.strip() for domain in domains]

    data = ()
    index = 1
    count = len(domains)

    for domain in domains:
        data = data + ([index, domain],)
        index = index + 1

    parser = Parser()
    detector = Detector()
    evaluator = Evaluation(count)

    total_dangerous = Value('i', 0)
    total_suspicious = Value('i', 0)
    total_safe = Value('i', 0)

    total_xss = Value('i', 0)
    total_blacklist = Value('i', 0)
    total_redirects = Value('i', 0)
    total_yara = Value('i', 0)
    total_link_manipulation = Value('i', 0)

    total_links_blacklist = Value('i', 0)
    total_links_xss = Value('i', 0)

    pool = multiprocessing.Pool(20)
    pool.map(detect_website, data, chunksize=1)
