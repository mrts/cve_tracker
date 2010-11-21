"""
A script for checking the relation of CVE entries listed under keyword 'python'
to the Python issue tracker.

Checks for:
    * CVE -> Python: CVE refers to either bugs.python.org or svn.python.org
    * Python -> CVE: bugs.python.org refers to CVE

Copyleft Mart Somermaa, mrts dot pydev at gmail dot com, usage under the Python licence.
"""
from lxml import html
from lxml.etree import XPath
from urlparse import urljoin
import re

# put any CVE identifiers that should be ignored here
# ---
IGNORED_LIST = (
    'CVE-2009-3850', 'CVE-2009-3695', 'CVE-2009-3578', 'CVE-2009-2940',
    'CVE-2009-0668', 'CVE-2009-0367', 'CVE-2008-6954', 'CVE-2008-6547',
    'CVE-2008-6539', 'CVE-2008-5102', 'CVE-2008-4863', 'CVE-2008-4394',
    'CVE-2008-3949', 'CVE-2008-3294', 'CVE-2008-0982', 'CVE-2008-0981',
    'CVE-2008-0980', 'CVE-2008-0299', 'CVE-2007-6015', 'CVE-2007-5741',
    'CVE-2007-4308', 'CVE-2007-1359', 'CVE-2007-1253', 'CVE-2006-7228',
    'CVE-2006-0151', 'CVE-2006-0052', 'CVE-2005-3302', 'CVE-2005-3291',
    'CVE-2005-3008', 'CVE-2005-2966', 'CVE-2005-2875', 'CVE-2005-2491',
    'CVE-2005-2483', 'CVE-2005-0852', 'CVE-2004-1050', 'CVE-2003-0973',
    'CVE-2002-0131',
)
# ---

CVE_URL = "http://cve.mitre.org"
CVE_LIST = urljoin(CVE_URL, "/cgi-bin/cvekey.cgi?keyword=python")
CVE_LINKS_XPATH = XPath("id('TableWithRules')/table/tr/td[1]/a")

CVE_BUGS_XPATH = XPath("id('GeneratedTable')/table/tr/td/ul/li/a/text()")
CVE_DESC_XPATH = XPath("id('GeneratedTable')/table/tr[4]/td/text()")
CVE_BUGS_ROUNDUP_RE = re.compile("http://bugs.python.org/issue(\d+)")
CVE_BUGS_SVN_RE = re.compile("http://svn.python.org/\S+rev=(\d+)")

ROUNDUP_XPATH = XPath("id('content')/table/tr/td[2]/text()")
ROUNDUP_SEARCH_URL = "http://bugs.python.org/issue?@search_text=%s"


class CVE(object):
    def __init__(self, name, link):
        root = html.parse(urljoin(CVE_URL, link)).getroot()
        self.refs = CVE_BUGS_XPATH(root)
        self.desc = CVE_DESC_XPATH(root)[0]
        self.name = name
        self.bugs = []
        self.svn_entries = []

    @property
    def has_bug_links(self):
        _re_search(self.refs, CVE_BUGS_ROUNDUP_RE, self.bugs)
        return bool(self.bugs)

    @property
    def has_svn_links(self):
        _re_search(self.refs, CVE_BUGS_SVN_RE, self.svn_entries)
        return bool(self.svn_entries)

    @property
    def listed_in_roundup(self):
        root = html.parse(ROUNDUP_SEARCH_URL % self.name.lower()).getroot()
        self.bugs.extend(ROUNDUP_XPATH(root))
        return bool(self.bugs)

def get_cve_list():
    root = html.parse(CVE_LIST).getroot()
    links = CVE_LINKS_XPATH(root)
    return (CVE(a.text, a.get('href')) for a in links
            if not a.text in IGNORED_LIST)

def main():
    warn = 0
    err = 0
    ok = 0

    for cve in get_cve_list():
        if cve.has_bug_links:
            ok += 1
            print("===\n%s OK: bugs.python.org issues %s listed in CVE\n---\n%s"
                    % (cve.name, cve.bugs, cve.desc))
            continue
        if cve.has_svn_links:
            warn += 1
            print("===\n%s WARN: only svn.python.org SVN revisions %s listed in CVE"
                    % (cve.name, cve.svn_entries))
            if cve.listed_in_roundup:
                print("\tbut it is referred to in bugs.python.org issues %s"
                        % cve.bugs)
            print("---\n%s" % cve.desc)
            continue
        if cve.listed_in_roundup:
            warn += 1
            print("===\n%s WARN: no references to issues or SVN in CVE\n"
                    "\tbut it is referred to in bugs.python.org issues %s"
                    "\n---\n%s"
                    % (cve.name, cve.bugs, cve.desc))
            continue
        err += 1
        print("===\n%s ERROR: no references to python.org issues or SVN in CVE\n"
                "\tnor do any bugs.python.org issues refer to it\n---\n%s"
                % (cve.name, cve.desc))

    print("--------------------------------------------------\n"
            "There were %(err)d errors, %(warn)d warnings and "
            "%(ok)d CVEs were OK." % locals())

def _re_search(refs, regex, result):
    for ref in refs:
        match = regex.search(ref)
        if match:
            result.append(match.group(1))

if __name__ == '__main__':
    main()
