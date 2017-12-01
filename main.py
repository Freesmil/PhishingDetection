#!/usr/bin/env python

import ipaddress
import multiprocessing
import os
import psycopg2
import subprocess
import sys
import ujson
import urllib
import yara
from bs4 import BeautifulSoup
from multiprocessing import Value
from pylibs.urlnorm.urlnorm_ext import get_first_level_domain
from pylibs.urlnorm.urlnorm_ext import get_hostname
from termcolor import cprint
from urllib.parse import urlparse


class Database:

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
        
        :param str domain: string 
        :return: boolean
        :rtype: boolean
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

        result = cur.fetchall()

        if not result:
            return False

        #cprint("Domain " + domain + " is in database blacklist.", 'green')
        return True

    def is_domain_in_whitelist(self, domain):
        """
        Checks if domain is in the DB whitelist. If yes returns true else false

        :param domain: string 
        :return: boolean
        """

        cur = self.conn.cursor()

        try:
            cur.execute("""SELECT domain FROM whitelist WHERE domain=%s""", (domain,))
        except psycopg2.DatabaseError:
            cprint("DATABASE ERROR: Execution of SELECT failed", 'red')

        result = cur.fetchall()

        if not result:
            return False

        cprint("Domain " + domain + " is in database whitelist.", 'green')
        return True


class Parser:

    def __init__(self):
        """
        Constructor.  
        """

    def parse(self, domain, html_before, html_after):

        links = self.get_links(domain, html_before)

        for link in self.get_links(domain, html_after):
            links.add(link)

        result = {'domain': domain,
                  'html': html_after,
                  'links': links,
                  'links_outside': self.get_outside_links(domain, links)}

        return result


    def get_links(self, domain, html):
        """
        Gets html DOM and returns links from elements 'a' and 'link' in 'body'.

        :return: set
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
        Gets links and return links which are outside of the domain.

        :return: set 
        """

        outside_links = set()

        for link in links:
            if (link.find("http://") == 0 or link.find("https://") == 0) \
                    and (get_first_level_domain(link) != domain):
                outside_links.add(link)

        return outside_links


class Detector:

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
        links = parsed_domain['links']

        result = {'name': parsed_domain['domain']}
        result['domain'] = self.link_detection(parsed_domain['domain'], True)
        result['html'] = {}
        result['html']['links'] = {}
        result['html']['links_outside_count'] = len(parsed_domain['links_outside'])
        result['html']['links_count'] = len(parsed_domain['links'])
        result['html']['redirects'] = self.redirects_detection(parsed_domain['html'], parsed_domain['domain'])
        self.yara_detection(parsed_domain['html'])
        result['html']['yara'] = self.yara_matches

        for link in links:
            result['html']['links'][link] = self.link_detection(link)

        return result

    def link_detection(self, link, whitelist = False):
        result =  {'name': link}
        result['blacklist'] = self.database.is_domain_in_blacklist(link)
        if whitelist:
            result['whitelist'] = self.database.is_domain_in_whitelist(link)
        result['count_subdomains'] = self.link_count_subdomains(link)
        result['ip'] = self.link_is_ip_address(link)
        result['xss'] = self.is_link_xss(link)

        return result

    def link_is_ip_address(self, link):
        """
        If link is IP address returns true else false
        
        :return: bool 
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

    def link_count_subdomains(self, link):
        """
        Counts how many link has got
        for meta in code('meta'):
        :return: int
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
                #cprint(" ------ ++++ ------ XSS FOUND", 'blue')
                return True

        return False

    def redirects_detection(self, code, domain):

        redirects = dict()
        redirects['outside'] = self.redirects_html(code, domain) + self.redirects_js(code.prettify(), domain)

        return redirects

    def redirects_js(self, code, domain):
        count = 0

        return count

    def redirects_html(self, code, domain):
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


class Evaluation:
    def __init__(self, count):
        """
        Constructor.

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
        links = detection_result['html']['links']

        result = detection_result

        result['html']['links'] = {'blacklist': 0,
                                   'ip': 0,
                                   'count_subdomains': 0,
                                   'xss': 0
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

        status = "safe"
        statuscolor = "green"

        if((result['domain']['blacklist'] is True) or (result['domain']['xss'] is True) or (result['html']['yara'] > 0)):
            status = "dangerous"
        elif((result['html']['links']['blacklist'] > 0) or (result['html']['links']['xss'] > 0) or (result['html']['links']['ip'] > 0) \
                or (result['html']['links']['count_subdomains'] > 0) or (result['domain']['ip'] is True) or (result['html']['redirects']['outside'] > 0) \
                or (result['html']['yara'] > 0)):
            status = "suspicious"

        result['domain']['status'] = status

        self.print(result)

        self.count_total(result)

        self.print_total(index)

    def count_total(self, result):
        if(result['domain']['status'] == 'dangerous'):
            total_dangerous.value += 1
        if(result['domain']['status'] == 'suspicious'):
            total_suspicious.value += 1
        if(result['domain']['status'] == 'safe'):
            total_safe.value += 1

        if(result['domain']['xss'] is True):
            total_xss.value += 1
        if(result['domain']['blacklist'] is True):
            total_blacklist.value += 1
        if(result['html']['redirects'] is True):
            total_redirects.value += 1
        if(result['html']['yara'] is True):
            total_yara.value += 1

        if((result['html']['links']['blacklist'] > 0)):
            total_links_blacklist.value += 1

        if ((result['html']['links']['xss'] > 0)):
            total_links_xss.value += 1

        if ((result['html']['links']['ip'] > 0) \
                or (result['html']['links']['count_subdomains'] > 0)):
            total_links_blacklist.value += 1

    def print(self, result):
        cprint(" --- ", "grey")
        cprint("Domain: " + result['name'], 'cyan')
        cprint("    Domain is " + result['domain']['status'])
        cprint("    Blacklist: " + str(result['domain']['blacklist']), 'white')
        cprint("    IP: " + str(result['domain']['ip']), 'white')
        cprint("    XSS: " + str(result['domain']['xss']), 'white')
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
        cprint(" --- ", "grey")
        cprint(str(index) + "/" + str(self.count) + " are processed")
        cprint("Dangerous domains: " + str(total_dangerous.value), "white")
        cprint("Suspicious domains: " + str(total_suspicious.value), "white")
        cprint("Safe domains: " + str(total_safe.value), "white")

        cprint("XSS: " + str(total_xss.value), "white")
        cprint("Blacklist: " + str(total_blacklist.value), "white")
        cprint("Redirect: " + str(total_redirects.value), "white")
        cprint("Yara: " + str(total_yara.value), "white")
        cprint("Link manipulation: " + str(total_link_manipulation.value), "white")
        cprint("Links blacklist: " + str(total_links_blacklist.value), "white")
        cprint("Links XSS: " + str(total_links_xss.value), "white")


def detect_website(data):
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

    pool = multiprocessing.Pool(5)
    pool.map(detect_website, data, chunksize=1)





