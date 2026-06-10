import {getOctokit,context} from '@actions/github';
import * as dotenv from 'dotenv';
dotenv.config();

export class TestGraph{
    private client: any;

    constructor(private token:string = process.env.GITHUB_TOKEN || '') {
      const baseUrl = process.env.GITHUB_API_URL || 'https://api.github.com';
      this.client = getOctokit(token, { baseUrl }); 
    }
    // ,filterBy: {states: OPEN}
    public async getIssues ()  {
        console.log('getIssues - START');
        const query = `query IsslesTitle($organization: String!,$repo: String!, $count: Int!) {
            repository(name: $repo, owner: $organization) {
              issues(first: $count) {
                edges {
                  node {
                    title
                    number
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }`;

        const nextQuery = `query IsslesTitle($organization: String!, $count: Int!, $endCursor: String!,$repo: String!) {
            repository(name: $repo, owner: $organization) {
              issues(first: $count,after: $endCursor) {
                edges {
                  node {
                    title
                    number
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }`;
        
        let issues:Array<{
            node: {
                title: string,
                number: number
            }
        }> = [];
        try {
            let issuesRes: any = await this.client.graphql({
                headers: {
                    authorization: `token ${this.token}`
                },
                query,
                count: 2,
                organization: process.env.ORG,
                repo: process.env.REPO
            });
             
            console.log(JSON.stringify(issuesRes,null,2));
            issues = issues.concat(issuesRes.repository.issues.edges);
            console.log(issues);

            console.log(issuesRes.repository.issues.pageInfo.hasNextPage);
            while (issuesRes.repository.issues.pageInfo.hasNextPage) {
                const endCursor =issuesRes.repository.issues.pageInfo.endCursor;

                issuesRes = await this.client.graphql({
                    headers: {
                        authorization: `token ${this.token}`
                    },
                    query:nextQuery,
                    count: 2,
                    endCursor:`${endCursor}`,
                    organization: process.env.ORG,
                    repo: process.env.REPO
                });
                issues = issues.concat(issuesRes.repository.issues.edges);
                console.log(issues);
            }

        } catch (e) {
            console.log('=======================   ERROR   ===============================');
            console.log(e);
          
        }
        console.log('getIssues - END');
        return issues;
    }
}

const handler = new TestGraph(process.env.GITHUB_TOKEN);
handler.getIssues();

