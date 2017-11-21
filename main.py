#!/usr/bin/env python

import ipaddress
import psycopg2
import subprocess
import sys
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
        
        :param domain: string 
        :return: boolean
        """

        cur = self.conn.cursor()

        try:
            cur.execute("""SELECT domain FROM blacklist WHERE domain=%s""", (domain,))
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

    def __init__(self, html, domain_name):
        """
        Constructor.  
              
        :param html: BeautifulSoup
        :param domain_name: string
        """
        self.domain = domain_name
        self.html = html
        self.links = self.get_href_links()
        self.links_outside = self.get_outside_links()

    def get_href_links(self):
        """
        Gets html DOM and returns links from elements 'a' and 'link' in 'body'.

        :return: set
        """

        links = set()
        for a in self.html('a'):
            try:
                links.add(a['href'])
            except KeyError:
                continue

        try:
            for a in self.html.body('link'):
                try:
                    links.add(a['href'])
                except KeyError:
                    continue
        except:
            cprint("INFO: domain " + self.domain + " has no body element", 'cyan')
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

    def get_outside_links(self):
        """
        Gets links and return links which are outside of the domain.

        :return: set 
        """

        outside_links = set()

        for link in self.links:
            if (link.find("http://") == 0 or link.find("https://") == 0) \
                    and (get_first_level_domain(link) != domain):
                outside_links.add(link)

        return outside_links


class LinkModel:

    def __init__(self, link):
        """
        Constructor.
        
        :param link: string
        """

        self.link = link
        self.ip_address = self.is_ip_address()
        self.count_subdomains = self.count_subdomains()

    def is_ip_address(self):
        """
        If link is IP address returns true else false
        
        :return: bool 
        """
        try:
            ipaddress.ip_address(self.link)
            return True
        except ValueError:
            return False

    def count_subdomains(self):
        """
        Counts how many link has got
        
        :return: int
        """

        count = 0

        hostname = get_hostname(self.link)
        try:
            count = hostname.replace(get_first_level_domain(hostname), '').count('.')
        except:
            return 0

        if count > 5:
            cprint("Link " + link + " has more than 5 subdomains.", 'orange')

        return count

    
if __name__ == "__main__" : 
    
    domain_file = sys.argv[1]

    with open(domain_file, 'r') as input_file:
        domains = input_file.readlines()

    domains = [domain.strip() for domain in domains]

    database = Database()

    for domain in domains:

        # domain = database.is_domain_in_blacklist(domain)
        # domain = database.is_domain_in_whitelist(domain)

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
            cprint("WARNING: Wget returned empty page, domain: " + domain, 'red')
            continue

        if html_after_js is None:
            cprint("WARNING: Chrome returned empty page, domain: " + domain, 'red')
            continue

        original_page = Parser(html_before_js, domain)
        page_after_js = Parser(html_after_js, domain)

        links = page_after_js.links_outside - original_page.links_outside

        links.add(domain)

        processed_links = []

        for link in links:
            result = LinkModel(link)
            result.blacklist = database.is_domain_in_blacklist(link)
            result.whitelist = database.is_domain_in_whitelist(link)
            processed_links.append(result)


        cprint('--- URL: ' + domain, 'yellow')
        print('    Total links before: ', len(original_page.links))
        print('    Total links after: ', len(page_after_js.links))
        print('    Outside links before: ', len(original_page.links))
        print('    Outside links after: ', len(original_page.links_outside))
        # print('    Outside: ', page_after_js.links_outside)
        # document.documentElement.outerHTML;
