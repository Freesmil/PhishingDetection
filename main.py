#!/usr/bin/env python


import ipaddress
import requests
import subprocess
import sys
from bs4 import BeautifulSoup
from pylibs.urlnorm.urlnorm_ext import get_first_level_domain
from pylibs.urlnorm.urlnorm_ext import get_hostname


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
        except TypeError:
            print("INFO: domain " + self.domain + " has no body element")
            return set()

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


class LinksModel:

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
        Couns how many link has got
        
        :return: int
        """

        count = 0
        
        hostname = get_hostname(self.link)
        count = hostname.replace(get_first_level_domain(hostname), '').count('.')

        return count

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
        print("WARNING: Something has gone wrong with executing wget, domain: " + domain)
        continue
    except subprocess.TimeoutExpired:
        print("WARNING: Something has gone wrong with executing wget (timeout expired), domain: " + domain)
        continue

    try:
        output_after_js = subprocess.check_output(['bash', '-c', bash_command_after_js], timeout=15)
    except subprocess.CalledProcessError:
        print("WARNING: Something has gone wrong with executing Chrome, domain: " + domain)
        continue
    except subprocess.TimeoutExpired:
        print("WARNING: Something has gone wrong with executing Chrome (timeout expired), domain: " + domain)
        continue

    html_before_js = BeautifulSoup(output_before_js, 'html.parser')
    html_after_js = BeautifulSoup(output_after_js, 'html.parser')

    if html_before_js is None:
        print("WARNING: Wget returned empty page, domain: " + domain)
        continue

    if html_after_js is None:
        print("WARNING: Chrome returned empty page, domain: " + domain)
        continue

    original_page = Parser(html_before_js, domain)
    page_after_js = Parser(html_after_js, domain)

    for link in page_after_js.links_outside:
        result = LinksModel(link)

    different_links = page_after_js.links_outside - original_page.links_outside
"""
    print('--- URL: ', domain)
    print('    Total links before: ', len(original_page.links))
    print('    Total links after: ', len(page_after_js.links))
    print('    Outside links before: ', len(original_page.links))
    print('    Outside links after: ', len(original_page.links_outside))
    print('    Outside: ', page_after_js.links_outside)
"""