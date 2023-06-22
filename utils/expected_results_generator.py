import csv
import os
import sys
from dataclasses import dataclass
from typing import Optional
from har_manager import print_from_har, send_from_har, urls_from_har
import urllib.parse
from my_har_parser import get_har_file, get_categories, get_har_sessions

header = ['# test name','category', 'sub-cat', 'real vulnerability', 'cwe','Benchmark version: 1.8','date']
RESULT_NAME = "extra_expected_results_reinforced_wavsep-1.8.csv"



class OwaspReinforcedMap:
    """
    The following class maps the CWE, owasp categories and reinforced wavsep 
    OWASP and CWE: 
        cmdi,78
        crypto,327
        hash,328
        ldapi,90
        pathtraver,22
        securecookie,614
        sqli,89
        trustbound,501
        weakrand,330
        xpathi,643
        xss,79

    REINFORCED: 
        lfi
        open-redirect
        os
        rfi
        sql
        xss
        xxe 
    """

    def __init__(self, owasp_cat, reinforced_cat, cwe):
        self.owasp_cat = owasp_cat
        self.reinforced_cat = reinforced_cat
        self.cwe = cwe 



mappings = [
    OwaspReinforcedMap('cmdi', 'os', '78'),
    OwaspReinforcedMap('cmdi', 'os', '78'),
    OwaspReinforcedMap('pathtraver', 'lfi', '22'),
    OwaspReinforcedMap('pathtraver', 'rfi', '22'),
    OwaspReinforcedMap('redirect', 'open-redirect', '601'),
    OwaspReinforcedMap('xss', 'xss', '79'),
    OwaspReinforcedMap('xpathi', 'xxe', '643'),
    OwaspReinforcedMap('sqli', 'sql', '89'),
]

def find_map(reinforced_cat: str): 
    global mappings
    for m in mappings: 
        if m.reinforced_cat == reinforced_cat:
            return m



class my_dialect(csv.excel):
    lineterminator = csv.unix_dialect.lineterminator
csv.register_dialect("excelnix", my_dialect)



def write_csv(rows):
    with open(RESULT_NAME, 'w', newline =  '') as csvfile: 
        csvwriter = csv.writer(csvfile, dialect="excelnix")
        csvwriter.writerow(header)
        csvwriter.writerows(rows)



def false_positive_convert(string):
    # remove the suffix
    string = string.split("-")[0]
    # convert to lowercase
    string = string.lower()
    # remove non-alphabetic characters
    # Output: ['lfi', 'sinjection', 'rfi', 'redirect', 'rxss']
    string = ''.join(e for e in string if e.isalnum())
    if string == 'sinjection': 
        string = 'sql'
    if string == 'redirect':
        string = 'open-redirect'
    if string == 'rxss':
        string = 'xss'

    return string



def e():
    sys.exit(-1)

def p(a):
    print("[+] {}".format(a))


def extract_testname(url):
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path
    file_name = path.split("/")[-1]
    return os.path.splitext(file_name)[0]



p("Get har sessions")
rows = []
special_rows = []


def get_urls(category, sessions):
    urls = []
    for s in sessions: 
        filepath = get_har_file(category, s)
        new_urls = urls_from_har(filepath)
        urls = urls + [{
            "url": url,
            "session": s,
            "filepath": filepath,
        } for url in new_urls]
    return urls



har_sessions = get_har_sessions()

for category, sessions in har_sessions.items():
    if category != 'false-positives':
        m = find_map(category)
        urls = get_urls(category, sessions)
        for url in urls:
            #print(f"    URL {url}")
            u = url['url']
            session = url['session'].rstrip(".har")
            testname = extract_testname(u)
            """ 
            # test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
                BenchmarkTest00001,pathtraver,true,22
                BenchmarkTest00002,pathtraver,true,22

            """
            prepend_testname = {
                "js3": "Case01-",
                "js4_dq": "Case02-",
                "js6_sq": "Case03-",
            }
            prefix = prepend_testname.get(testname, None)
            if prefix is not None:
                testname = prefix + testname

            if testname.startswith('Case'):
                rows.append([testname, m.owasp_cat, session, 'true', m.cwe])
                if prefix is not None:
                    special_rows.append(rows[-1])
                continue

            print()
            print(testname)
            print(url["filepath"])
            print("hello", u)

    else:
        for s in sessions: 
            filepath = get_har_file(category, s)
            real_category = false_positive_convert(s)
            m = find_map(real_category)
            urls = urls_from_har(filepath)
            # urls = get_urls(category, sessions)
            for u in urls: 
                testname = extract_testname(u)
                if testname.startswith('Case'):
                    rows.append([testname,  m.owasp_cat, s, 'false', m.cwe])
                else:
                    raise ValueError(u)

if False:
    for row, next_row in zip(rows, rows[1:] + [None]):
        if len(row) != 2:
            continue
        print(row)
        print(next_row)
        print()

print()
write_csv([
    [name, oc, irv, cwe]
    for name, oc, s, irv, cwe in sorted(special_rows)
])
p("File written to {}".format(RESULT_NAME))


@dataclass
class GBTestCase:
    name: str
    owasp_category: str
    is_real_vuln: bool
    cwe_number: int
    main_url: str
    entry_url: Optional[str]

    @classmethod
    def munch_rows(cls, rows):
        extra = []
        for row_id, row in enumerate(rows):
            if row[0] is None:
                extra = row[1:]
                continue
            yield cls(*(row + extra))
            extra = []

