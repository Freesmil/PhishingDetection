#!/usr/bin/env python


import ipaddress
import sys
from bs4 import BeautifulSoup


class Parser:

    def __init__(self, file_name):
        """
        Constructor.  
              
        :param file_name: string 
        """

        self.file_name = file_name
        self.html = self.get_soup_page()
        self.links = self.get_href_links()
        self.links_outside = self.get_outside_links()

    def get_soup_page(self):
        """
        This method gets DOM (html) and return BeautifulSoup object.

        :return: BeautifulSoup 
        """

        with open(self.file_name, 'r', encoding='ISO-8859-2') as input_file:
            html = input_file.read()

        return BeautifulSoup(html, 'html.parser')

    def get_href_links(self):
        """
        Gets html DOM and returns links from elements 'a' and 'link' in 'body'.

        :return: set
        """

        links = []

        for a in self.html.body('a'):

            try:
                links.append(a['href'])
            except KeyError:
                links = []

        for a in self.html.body('link'):
            try:
                links.append(a['href'])
            except KeyError:
                links = []

        return links

    def get_outside_links(self):
        """
        Gets links and return links which are outside of the domain.

        :return: set 
        """

        outside_links = []

        for link in self.links:
            if (link.find("http://") == 0 or link.find("https://") == 0)\
                    and (link.find("://"+sys.argv[3]) == -1 and link.find("://www."+sys.argv[3]) == -1):
                outside_links.append(link)

        return outside_links


class LinksModel:

    def __init__(self, link):
        """
        Constructor.
        
        :param link: string 
        """

        self.link = link
        self.ip_address = self.is_ip_address()

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


original_page = Parser(sys.argv[1])
page_after_js = Parser(sys.argv[2])


different_links = (set(page_after_js.links_outside) - set(original_page.links_outside))


print('--- URL: ', sys.argv[3])
print('    Total links before: ', len(original_page.links))
print('    Total links after: ', len(page_after_js.links))
print('    Outside links before: ', len(original_page.links))
print('    Outside links after: ', len(original_page.links_outside))
print('    Differences: ', different_links)
