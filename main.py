#!/usr/bin/env python

import ipaddress
import psycopg2
import subprocess
import sys
import urllib
from bs4 import BeautifulSoup
from pylibs.urlnorm.urlnorm_ext import get_first_level_domain
from pylibs.urlnorm.urlnorm_ext import get_hostname
from termcolor import cprint


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

        cprint("Domain " + domain + " is in database blacklist.", 'green')
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
                  'links_outside': self.get_outside_links(links)}

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
            cprint("INFO: domain " + domain + " has no body element", 'cyan')
            return set()

        for link in links:
            try:
                if link.index('@') > 0:
                    position = link.index('@')
                    links.add(link[:position])
                    links.add(link[position+1:])
            except ValueError:
                continue

        return links

    def get_outside_links(self, links):
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

    def detection(self, parsed_domain):
        links = parsed_domain['links']

        result = {'name': parsed_domain['domain']}
        result['domain'] = self.link_detection(parsed_domain['domain'], True)
        result['html'] = {}
        result['html']['links'] = {}
        result['html']['redirects'] = self.redirects_detection(parsed_domain['html'])
        result['html']['yara'] = self.yara_detection(parsed_domain['html'])

        for link in links:
            result['html']['links'][link] = self.link_detection(link)

        return result

    def link_detection(self, link, whitelist = False):
        result =  {'name': link}
        result['blacklist'] = self.database.is_domain_in_blacklist(link)
        if whitelist:
            result['whitelist'] = self.database.is_domain_in_whitelist(link)
        result['count_subdomains'] = self.link_count_subdomains(link)
        result['ip_address'] = self.link_is_ip_address(link)
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
        
        :return: int
        """

        count = 0

        hostname = get_hostname(link)
        try:
            count = hostname.replace(get_first_level_domain(hostname), '').count('.')
        except:
            return 0

        return count

    def is_link_xss(self, link):
        return False

    def redirects_detection(self, code):
        return False

    def yara_detection(self, code):
        return False


class Evaluation:
    def __init__(self):
        """
        Constructor.

        """

    def evaluate(self, detection_result):
        result = detection_result

        self.print_result(result)

    def print_result(self, evaluation):
        print("Y")


if __name__ == "__main__" :
    domain_file = sys.argv[1]

    with open(domain_file, 'r') as input_file:
        domains = input_file.readlines()

    domains = [domain.strip() for domain in domains]


    for domain in domains:

        bash_command_before_js = 'wget -qO- -t 1 --connect-timeout=5 http://' + domain
        bash_command_after_js = 'google-chrome-stable --headless --timeout=5000 --virtual-time-budget=5000 --disable-gpu' \
                                ' --dump-dom http://' + domain

        try:
            output_before_js = subprocess.check_output(['bash', '-c', bash_command_before_js], timeout=15)
        except subprocess.CalledProcessError:
            cprint("WARNING: Something has gone wrong with executing wget, domain: " + domain, 'red')
            continue
        except subprocess.TimeoutExpired:
            cprint("WARNING: Something has gone wrong with executing wget (timeout expired), domain: " + domain, 'red')
            continue

        try:
            output_after_js = subprocess.check_output(['bash', '-c', bash_command_after_js], timeout=15)
        except subprocess.CalledProcessError:
            cprint("WARNING: Something has gone wrong with executing Chrome, domain: " + domain, 'red')
            continue
        except subprocess.TimeoutExpired:
            cprint("WARNING: Something has gone wrong with executing Chrome (timeout expired), domain: " + domain, 'red')
            continue

        html_before_js = BeautifulSoup(output_before_js, 'html.parser')
        html_after_js = BeautifulSoup(output_after_js, 'html.parser')

        try:
            html_before_js.prettify()
            html_after_js.prettify()
        except Exception:
            continue

        if html_before_js is None:
            cprint("WARNING: Wget returned empty web page, domain: " + domain, 'red')
            continue

        if html_after_js is None:
            cprint("WARNING: Chrome returned empty web page, domain: " + domain, 'red')
            continue

        parser = Parser()
        parsed_domain = parser.parse(domain, html_before_js, html_after_js)

        detector = Detector()

        detection_result = detector.detection(parsed_domain)

        evaluator = Evaluation()
        evaluator.evaluate(detection_result)


