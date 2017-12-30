# Github Spider
# This will spider through a Github repository for an org and search the org repos, find members, their repos, etc
import requests
import re
import configparser
import argparse
from customConstants import *

class Spider(object):
    def __init__(self):
        config = configparser.ConfigParser()
        config.read("config/github_checks_config.txt")
        ext_api = config.get("github_api", "ext_api")
        self.headers = {'Accept': 'application/vnd.github.v3+json', 'Authorization': 'token {}'.format(ext_api)}

    def pull_base_org(self, org):
        self.org = org
        self.org_info = requests.get('https://api.github.com/orgs/{}'.format(org), headers=self.headers)
        self.org_members = requests.get('https://api.github.com/orgs/{}/members'.format(org), headers=self.headers)
        self.repos = requests.get('https://api.github.com/orgs/{}/repos'.format(org), headers=self.headers)

    def get_user_info(self):
        user_data = {}
        for user in self.org_members.json():
            login = user['login']
            user_data[login] = []
            # Basic user info
            info = requests.get('https://api.github.com/users/{}'.format(login), headers=self.headers)
            # User's repositories
            user_repos = requests.get('https://api.github.com/users/{}/repos'.format(login), headers=self.headers)
            # Who is the user following
            user_following_json = requests.get('https://api.github.com/users/{}/following'.format(login), headers=self.headers)

            user_following = []
            for following in user_following_json.json():
                follower_info = requests.get('https://api.github.com/users/{}'.format(following['login']), headers=self.headers)
                #print(follower_info.json()['company'])
                user_following.append(following['login'])
                if follower_info.json()['company'] and re.search(self.org, follower_info.json()['company'], re.IGNORECASE):
                    print("{} is following {} who appears to be in {}".format(login, following['login'], custom_org))
            user_data[login].append({'Following': user_following})

            for repo in user_repos.json():
                full_repo_info = requests.get(repo['url'], headers=self.headers)
                if full_repo_info.json()['fork'] == True:
                    parent = full_repo_info.json()['parent']['html_url']
                    print("{} --> {}: Repo forked from: {}".format(login, repo['name'], parent))
                    if re.search(self.org, parent, re.IGNORECASE):
                        print("{} --> {}: Forked from search org: {}".format(login, repo['name'], self.org))
                else:
                    print("{} --> {}: Unique user repo".format(login, repo['name']))
                    commits = requests.get('https://api.github.com/repos/{}/{}/commits'.format(login, repo['name']), headers=self.headers)
                    forks = requests.get('https://api.github.com/repos/{}/{}/forks'.format(login, repo['name']), headers=self.headers)
                    # , 'commits': commits.json()
                    user_data[login].append({'Repo_Name': repo['name'], 'Created': repo['created_at'], 'Updated': repo['updated_at'], 'forks': forks.json()})

        return user_data

    def get_org_repos(self):
        org_repos_data = []
        for repo in self.repos.json():
            commits = requests.get('https://api.github.com/repos/{}/{}/commits'.format(self.org, repo['name']), headers=self.headers)
            forks = requests.get('https://api.github.com/repos/{}/{}/forks'.format(self.org, repo['name']), headers=self.headers)
            org_repos_data.append({'Organization': self.org, 'Repo_Name': repo['name'], 'Created': repo['created_at'], 'Updated': repo['updated_at'], 'commits': commits.json(), 'forks': forks.json()})

        return org_repos_data

def parseargs():
    opts = argparse.ArgumentParser("""Github Spider""")
    opts.add_argument('-l', '--level', default=3, help='Number of depths/level to spider')
    opts.add_argument('-d', '--debug', action='store_true', default=False, help='Turn Debug on')
    opts.add_argument('-n', '--neo4j', action='store_true', default=False, help='Use Neo4j Graph Database')
    opts.add_argument('--flush_neo4j', action='store_true', default=False, help='*** USE CAUTION *** Flush the Neo4j Graph Database before starting')
    args = opts.parse_args()
    return(args)

if __name__ == '__main__':
    args = parseargs()

    if args.neo4j:
        from customNeo4j import *
        n4j = Neo4j(flush=args.flush_neo4j)
    spider = Spider()
    spider.pull_base_org(custom_org)
    member_data = spider.get_user_info()
    org_repos_data = spider.get_org_repos()
