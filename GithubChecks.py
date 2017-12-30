# Github Org and Repository Search Script
#  Ideas and some code taken from truffleHog project: https://github.com/dxa4481/truffleHog

# Requires Python 3.6 or greater due to the Formatted String Literals -- print(f"a is {a}")

import requests
import sys
import datetime
import logging
import re
import pymongo
import configparser
import argparse
import csv
from customConstants import *

if sys.version_info.major < 3 or (sys.version_info.major == 3 and sys.version_info.minor < 6):
    print("Python Version 3.6 or greater is required due to the Formatted String Literals [i.e., print(f\"a is {a}\")]")
    print(" Accept it, stop using Python2 - Python3 fixes and speeds scripts up -- deal with it even on your Windows XP system....")
    print(" OK, fine, I fixed the Formatted String Literals - but I'll still kill the program if you are not running Python 3.6 or greater")

debug = 1

regexes = {
    "Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "Slack Token": re.compile('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile('-----BEGIN RSA PRIVATE KEY-----'),
    "Facebook Oauth": re.compile('[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]'),
    "Twitter Oauth": re.compile('[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]'),
    "Google Oauth": re.compile('("client_secret":"[a-zA-Z0-9-_]{24}")'),
    "AWS API Key": re.compile('AKIA[0-9A-Z]{16}'),#[a|A][w|W][s|S].*AKIA[0-9A-Z]{16}'),
    "Heroku API Key": re.compile('[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    "Generic Secret": re.compile('[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]'),
    "AWS Secret Key from AWS Credentials": re.compile('aws_secret_access_key'),
    "AWS Access Key ID from AWS Credentials": re.compile('aws_access_key_id'),
    "AWS Secret Key Variable": re.compile('secret_access_key'),
    "AWS Access Key Variable": re.compile('access_key_id')
}

timestamp = datetime.datetime.now().strftime('%m-%d-%Y_%H%M')
logger = logging.getLogger('Github Regex Search')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("logs/github_regex_logs_{}.log".format(timestamp))
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
csv_outfile = "findings/findings_{}".format(timestamp)


config = configparser.ConfigParser()
config.read("config/github_checks_config.txt")
dbServer = config.get("MongoDB", "dbServer")
dbPort = config.get("MongoDB", "dbPort")
dbName = config.get("MongoDB", "dbName")
dbUser = config.get("MongoDB", "dbUser")
dbPassword = config.get("MongoDB", "dbPassword")

int_api = config.get("github_api", "int_api")
ext_api = config.get("github_api", "ext_api")

dbCollectionName = 'github_findings_{}'.format(timestamp)
dbStatsCollection = 'githubStats'
dbRepoCollection = 'githubRepos_{}'.format(timestamp)
dbConsolidatedCollection = 'consolidated_findings_{}'.format(timestamp)


client = pymongo.MongoClient(dbServer, username=dbUser, password=dbPassword, authSource=dbName, authMechanism='SCRAM-SHA-1')
db = client[dbName]
findings_coll = db[dbCollectionName]
stats_coll = db[dbStatsCollection]
repos_coll = db[dbRepoCollection]
consolidated_coll = db[dbConsolidatedCollection]
commit_test_coll = db.commits_test_9999
repos_test_coll = db.repos_test_9999
#all_commits_coll = db.all_commits_12_01_2017_1

stats = []    # stats: {org: [{repo_name: [repo_commits, repo_commit_findings]}]}
total_repos = {}
total_org_count = 0
github_all = []

headers = {'Accept': 'application/vnd.github.v3+json', 'Authorization': 'token {}'.format(int_api)}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Github_Check(object):
    '''Main class for the Github_Check script'''
    def __init__(self, args):
        self.int_check = args.internal
        self.ext_check = args.external
        self.nocheck = args.nosearch
        self.pull_commits = args.commits
        self.org = args.org

    def search_regexes(self, patch):
        _found = []
        find_it = patch.split('\n')
        for curLine in find_it:
            found_strings = {}
            for key in regexes:
                strings = regexes[key].findall(curLine)
                if strings:
                    for string in strings:
                        formatted_string = curLine.replace(curLine, bcolors.WARNING + string + bcolors.ENDC)
                        found_strings['foundString'] = string
                        found_strings['foundStringFormatted'] = formatted_string
                        found_strings['fullLine'] = curLine
                        found_strings['Reason'] = key
                        if debug: print("Found String: {}".format(found_strings['foundStringFormatted']))
                        _found.append(found_strings)
        return _found

    def pull_org_repos(self, org):
        return requests.get(url + "/orgs/{}/repos".format(org), headers=headers)

    def pull_repo_commits(self, org, repo_name):
        return requests.get(url + "/repos/{}/{}/commits".format(org, repo_name), headers=headers)

    def pull_each_commits(self, org, repo_name, sha):
        return requests.get(url + "/repos/{}/{}/commits/{}".format(org, repo_name, sha), headers=headers)

    def search_org_repos(self, org, url):
        org_repo_count = 0
        foundRegexes = []
        repos = self.pull_org_repos(org)
        print("Searching Organization: {}".format(org))
        logger.info("Searching Organization: {}".format(org))
        for repo in repos.json():
            #stats['ts']['org'][org]['repo'] = repo
            github_all.append({'org': org, 'repo': repo['name']})
            print("\tRepository: {}".format(repo['name']))
            logger.info("\tOrg:Repository: {}:{}".format(org, repo['name']))
            if repo['size'] == 0:
                foundRegexes.append({'repository': repo['name'], 'repository_size': 0})
                continue
            #stats[org][repo['name']] = {}
            repo_commits = 0
            repo_commit_findings = 0
            org_repo_count += 1
            all_commits = self.pull_repo_commits(org, repo['name'])
            for commit in all_commits.json():
                repo_commits += 1
                commit_info = self.pull_each_commits(org, repo['name'], commit['sha'])
                for fn in commit_info.json()['files']:
                    if not 'patch' in fn:
                        continue
                    patch = fn['patch']
                    found = self.search_regexes(patch)
                    if found:
                        findings = {}
                        repo_commit_findings += 1
                        print("\t*****Findings in: {}:{}*****".format(repo['name'], fn['filename']))
                        #print(f"\t\t{found}")
                        logger.warning("*****Findings in: {}:{}*****".format(repo['name'], fn['filename']))
                        logger.warning("\t{}".format(found))
                        findings['filename'] = fn['filename']
                        findings['repository'] = repo['name']
                        findings['hits'] = found
                        findings['validated'] = "Not validated"
                        foundRegexes.append(findings)
                #stats[org][repo['name']] = {'repo_commits': repo_commits, 'repo_commit_findings': repo_commit_findings}
                stats.append({'ts': timestamp, 'org': org, 'repo': repo['name'], 'stats': {'commits': repo_commits, 'findings': repo_commit_findings}})
                #stats['ts'][timestamp]['org'][org] = {'repo': repo['name'], {'repo_commits': repo_commits, 'repo_commit_findings': repo_commit_findings}}
        return foundRegexes

    def pull_commits_only(self, org):
        print("Searching Organization: {}".format(org))
        #repos = requests.get(int_url + "/orgs/{}/repos".format(org), headers=headers)
        repos = self.pull_org_repos(org)
        for r in repos.json():
            repos_coll.insert_one(r)
        for repo in repos.json():
            if repo['size'] == 0:
                continue
            print("\tRepository: {}".format(repo['name']))
            #all_commits = requests.get(int_url + "/repos/{}/{}/commits".format(org, repo['name']), headers=headers)
            all_commits = self.pull_repo_commits(org, repo['name'])
            for c in all_commits.json():
                commit_coll.insert_one(c)
            #for commit in all_commits.json():
            #    commit_info = requests.get(int_url + "/repos/{}/{}/commits/{}".format(org, repo['name'], commit['sha']), headers=headers)
            #    all_commits_coll.insert_one(commit_info.json())

    def do_internal_search(self, int_repos):
        allResults = {}
        allResults['org'] = {}
        for org in int_repos:
            org_results = self.search_org_repos(org, int_url)
            #####pull_commits_only(org)
            print
            #for cur in org_results:
            #    allResults = {'org': org, 'findings': cur}
            allResults['org'][org] = org_results
        return allResults

    def interpret_findings():
        orgs = {}
        org_names = []
        details = {}
        hits = findings_coll.find({'findings.hits': {'$exists': True}})
        for org in hits.distinct('org'):
            orgs[org] = findings_coll.find({'findings.hits': {'$exists': True}, 'org': org})
            org_names.append(org)
            curHits = []
            details[org] = []
            for curOrg in orgs[org]:
                for hit in curOrg['findings']['hits']:
                    if not hit['foundString'] in curHits and not hit['fullLine'] in curHits:
                        details[org].append({'repository': curOrg['findings']['repository'], 'filename': curOrg['findings']['filename'], 'Reason': hit['Reason'], 'foundString': hit['foundString'], 'fullLine': hit['fullLine']})
                        curHits.append(hit['foundString'])
                        curHits.append(hit['fullLine'])
            orgs[org].rewind()

        consolidated_findings = []
        for key in details:
            seen_fn = []
            for cur in details[key]:
                fn = cur['filename']
                if fn in seen_fn:
                    findings.append({'Reason': hit['Reason'], 'foundString': cur['foundString'], 'fullLine': cur['fullLine']})
                else:
                    findings = [{'Reason': hit['Reason'], 'foundString': cur['foundString'], 'fullLine': cur['fullLine']}]
                    seen_fn.append(fn)
                all_findings = {'filename': fn, 'regex_hits': findings}
            consolidated_findings.append({'org': key, 'findings': all_findings})
        for cur in consolidated_findings:
            consolidated_coll.insert_one(cur)

        print()
        print("--------------------------")
        print("Unique Findings Statistics")
        print("--------------------------")
        total_count = 0
        max_len = max([len(x) for x in details])
        if max_len < 13:
            max_len = 13

        for key in details:
            findings = len(details[key])
            total_count += findings
            print("{:{}} : {}".format(key, max_len, findings))
        print("                {}".format("-" * len(str(total_count))))
        print(f"Total Findings: {total_count}")
        print()

        reasons = {}
        for finding in consolidated_coll.find():
            for item in finding['findings']['regex_hits']:
                reason = item['Reason']
                if reason in reasons:
                    reasons[reason] += 1
                else:
                    reasons[reason] = 1
        print("-----------------------------------")
        print("Reasons for findings (consolidated)")
        for key in reasons:
            print(f"{key}: {reasons[key]}")

    def db_interpret():
        ''' Interpret the findings from the DB rather than pulling the data live'''
        repos_coll = db.repos_prod
        commits_coll = db.commits_prod
        repos_cursor = repos_coll.find()
        commits_cursor = commits_coll.find()
        foundRegexes = []

        for commit in commits_cursor:
            _split = commit['html_url'].split('/')
            org_name = _split[3]
            repo_name = _split[4]
            for cf in commit['files']:
                filename = cf['filename']
                if not 'patch' in cf:
                    continue
                patch = cf['patch']
                if 'commit' in commit:
                    date = commit['commit']['author']['date']
                else:
                    date = 'Unknown Date'
                #found = self.search_regexes(patch)
                found = search_regexes(patch)
                if found:
                    findings = {}
                    print("\t*****Findings in: {}:{}*****".format(repo_name, filename))
                    logger.warning("*****Findings in: {}:{}*****".format(repo_name, filename))
                    logger.warning("\t{}".format(found))
                    findings['filename'] = filename
                    findings['repository'] = repo_name
                    findings['org'] = org_name
                    findings['hits'] = found
                    findings['date'] = date
                    findings['validated'] = "Not validated"
                    foundRegexes.append(findings)

        org_findings = {}
        for cur in foundRegexes:
            if cur['org'] in org_findings:
                org_findings[cur['org']].append(cur)
            else:
                org_findings[cur['org']] = []
                org_findings[cur['org']].append(cur)
        consolidated_findings = []
        #details = {}
        for key in org_findings:
            seen_fn = []
            details = []
            for cur in org_findings[key]:
                curHits = []
                fn = cur['filename']
                if not fn in seen_fn:
                    seen_fn.append(fn)
                else:
                    continue
                for hit in cur['hits']:
                    if not hit['foundString'] in curHits and not hit['fullLine'] in curHits:
                            details.append({'repository': cur['repository'], 'filename': cur['filename'], 'Commit_Date': cur['date'], 'Reason': hit['Reason'], 'foundString': hit['foundString'], 'fullLine': hit['fullLine']})
                            curHits.append(hit['foundString'])
                            curHits.append(hit['fullLine'])
                    #if fn in seen_fn:
                    #    findings.append({'Reason': hit['Reason'], 'foundString': hit['foundString'], 'fullLine': hit['fullLine']})
                    #else:
                    #    findings = [{'Reason': hit['Reason'], 'foundString': hit['foundString'], 'fullLine': hit['fullLine']}]
                    #    seen_fn.append(fn)
                #all_findings = {'filename': fn, 'regex_hits': findings}
            consolidated_findings.append({'org': key, 'findings': details})

        consolidated_coll = db.consolidated_findings_prod
        for cur in consolidated_findings:
            consolidated_coll.insert_one(cur)
        c = consolidated_coll.find()
        total = {}
        for cur in c:
            a = []
            dates = []
            for find in cur['findings']:
                a.append(find['Reason'])
                if not find['Commit_Date'] in dates:
                    dates.append(find['Commit_Date'])

            #print("{}".format("-" * (len(cur['org']) + 4)))
            print("{}{}{}".format(u'\u250c', (u'\u2500' * (len(cur['org']) + 2)), u'\u2510'))
            #print("| {} |".format(cur['org']))
            print("{} {} {}".format(u'\u2502', cur['org'], u'\u2502'))
            #print("{}".format("-" * (len(cur['org']) + 4)))
            print("{}{}{}".format(u'\u2514', (u'\u2500' * (len(cur['org']) + 2)), u'\u2518'))

            print(" Total Findings: {}".format(len(a)))
            counts = Counter(a)
            for key in counts:
                print("\t{}: {}".format(key, counts[key]))
            print(" Date of most recent commit with findings:")
            dates.sort()hj
            print("\t{}".format(dates[len(dates)-1]))
            total[cur['org']] = [len(a), dates[len(dates)-1]]
            print()

        print("------------------------------------------------")
        print("Unique Findings Statistics with last commit date")
        print("------------------------------------------------")
        total_count = 0
        for key in total:
            print("  {:15}: {}\t{}".format(key, total[key][0], total[key][1]))
            total_count += total[key][0]
        print("                  {}".format("-" * len(str(total_count))))
        print(f"Total Findings:   {total_count}")
        print()

        csv_header = ['Org', 'Filename', 'Reason', 'Full Line']
        with open(csv_outfile, "w") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_header)
            writer.writeheader()
            for results in consol:
                org = results['org']
                for finding in results['findings']:
                    writer.writerow({'Org': org, 'Filename': finding['filename'], 'Reason': finding['Reason'], 'Full Line': finding['fullLine']})


def parseargs():
    opts = argparse.ArgumentParser("""Github Sensitive Information Scanner""")
    opts.add_argument('-n', '--nosearch', action='store_true', default=False, help='Just connect to the DB and don\'t run anything - should use with "ipython -i"')
    opts.add_argument('-d', '--debug', action='store_true', default=False, help='Turn Debug On - will just search a couple of orgs')
    opts.add_argument('-e', '--external', action='store_true', default=False, help='Search External Github.com')
    opts.add_argument('-i', '--internal', action='store_true', default=True, help='Search Internal Github Server')
    opts.add_argument('-s', '--server', default='https://github.mb-internal.com/api/v3', help='Specify different Github Server to search')
    opts.add_argument('-c', '--commits', action='store_true', default=False, help='Pull all commits down to DB, but no searching')
    opts.add_argument('--db', action='store_true', default=False, help='Perform analysis on already pulled information in the MongoDB')
    opts.add_argument('--org', help='Org to search - can set default in customConstants.py')
    #opts.add_argument('query', help="Query input to lookup, enclose in single quotes if there are spaces...")
    args = opts.parse_args()
    return(args)

if __name__ == '__main__':
    args = parseargs()
    GitHub = Github_Check(args)

    if not args.org:
        args.org = default_org

    print("Github Sensitive Data Search")
    logger.info("Github Sensitive Data Search")
    logger.info("Using {}".format(args.server))

    if args.nosearch:
        print("Starting up, connecting to DB and dumping to prompt")

    else:
        allResults = GitHub.do_internal_search(int_repos)
        #print(f"Total Orgs Searched: {total_org_count}")
        for key in allResults['org']:
            for cur in allResults['org'][key]:
                findings_coll.insert_one({'org': key, 'findings': cur})
        for stat in stats:
            stats_coll.insert_one(stat)

        for cur in github_all:
            repos_coll.insert_one(cur)

        interpret_findings()




#  consolidated_coll.find_one({'org': 'Analytics'})
#  findings_coll.find_one({'org': 'Analytics', 'findings.repository': 'collection'})
#  stats_coll.find_one({'ts': {'$exists': True}})
#  repos_coll.find_one()
