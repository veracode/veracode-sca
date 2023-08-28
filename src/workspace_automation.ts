import * as auth from './auth'
import Axios from "axios";
import { env } from "process";
import * as core from '@actions/core'
        
export async function workspace_automation(options:any) {
        //set the platform region and base API url
        const cleanedID = options.VID?.replace('vera01ei-','') ?? '';
        const cleanedKEY = options.VKEY?.replace('vera01es-','') ?? '';
        const REPO_NAME = env.GITHUB_REPOSITORY ?? '';

        if ( options.VID?.startsWith('vera01ei-') ) {
            core.info('Platform is ER');
            var API_BASE_URL = 'api.veracode.eu';
        }
        else {
            core.info('Platform is US');
            var API_BASE_URL = 'api.veracode.com';
        }

        //check if workspace exists
        var path = '/srcclr/v3/workspaces?filter%5Bworkspace%5D='+encodeURIComponent(REPO_NAME)
        var checkWorkspace = await Axios.request({
            method: 'GET',
            headers:{
                'Authorization': auth.generateHeader(path, 'GET', API_BASE_URL, cleanedID, cleanedKEY),
            },
            url: 'https://'+API_BASE_URL+path
        });
          
          var workspacesResults = checkWorkspace.data

          if ( workspacesResults.page.total_elements == 0 ){
            //worespace doesn't exists, create it
            core.info('workspace doesn\'t exists and needs to be created');

            var path = '/srcclr/v3/workspaces'
            var data = '{"name":"'+REPO_NAME+'"}'
            var checkWorkspace = await Axios.request({
                method: 'POST',
                headers:{
                    'Authorization': auth.generateHeader(path, 'POST', API_BASE_URL, cleanedID, cleanedKEY),
                    'Content-Type': 'application/json',
                },
                data,
                url: 'https://'+API_BASE_URL+path
            });
            core.info('workspace created - now get the workspace ID');
            var path = '/srcclr/v3/workspaces?filter%5Bworkspace%5D='+encodeURIComponent(REPO_NAME)
            var checkWorkspace = await Axios.request({
                method: 'GET',
                headers:{
                    'Authorization': auth.generateHeader(path, 'GET', API_BASE_URL, cleanedID, cleanedKEY),
                },
                url: 'https://'+API_BASE_URL+path
            });
            var workspaceLenght = workspacesResults.page.total_elements
            var workspaceID = workspacesResults._embedded.workspaces[0].id

          }
          else {
            //workspace exists, get the workspace ID
            core.info('workspace already exists, get the workspace ID');
            var workspaceLenght = workspacesResults.page.total_elements
            for ( var i = 0; i < workspaceLenght; i++ ){
                if ( workspacesResults._embedded.workspaces[i].name == REPO_NAME ){
                    var workspaceID = workspacesResults._embedded.workspaces[i].id
                }
            }
            core.info('workspace ID: '+workspaceID)
        }

        //check if agent exists
        var path = '/srcclr/v3/workspaces/'+workspaceID+'/agents'
        var checkAgents = await Axios.request({
            method: 'GET',
            headers:{
                'Authorization': auth.generateHeader(path, 'GET', API_BASE_URL, cleanedID, cleanedKEY),
            },
            url: 'https://'+API_BASE_URL+path
          });
          
        var workspacesIDResults = checkAgents.data

        if ( workspacesIDResults.hasOwnProperty('_embedded') ){
            //there are agents
            core.info('there are agents, check if correct agent exists');
            var agentsLenght = workspacesIDResults._embedded.agents.length
            for ( var i = 0; i < agentsLenght; i++ ){
                if ( workspacesIDResults._embedded.agents[i].name == 'veracode-sca-action' ){
                    var agentID = workspacesIDResults._embedded.agents[i].id
                }
            }
            if ( agentID != undefined ){
                core.info('agent ID: '+agentID+' - for agent with name "veracode-sca-action" - need to regenerate token')
                var path = '/srcclr/v3/workspaces/'+workspaceID+'/agents/'+agentID+'/token:regenerate'
                var createAgent = await Axios.request({
                    method: 'POST',
                    headers:{
                        'Authorization': auth.generateHeader(path, 'POST', API_BASE_URL, cleanedID, cleanedKEY),
                        'Content-Type': 'application/json',
                    },
                    url: 'https://'+API_BASE_URL+path
                });
                var SRCCLR_API_TOKEN = createAgent.data.access_token
                return SRCCLR_API_TOKEN

            }
            else {
                core.info('agent for "Veracode-GitHub-Action" doesn\'t exists and needs to be created');
                var path = '/srcclr/v3/workspaces/'+workspaceID+'/agents'
                var data = '{"agent_type": "CLI","name": "veracode-sca-action"}'
                var createAgent = await Axios.request({
                    method: 'POST',
                    headers:{
                        'Authorization': auth.generateHeader(path, 'POST', API_BASE_URL, cleanedID, cleanedKEY),
                        'Content-Type': 'application/json',
                    },
                    data,
                    url: 'https://'+API_BASE_URL+path
                });
                var SRCCLR_API_TOKEN = createAgent.data.token.access_token
                return SRCCLR_API_TOKEN
            }
        }
        else {
            //there are no agents
            core.info('there are no agents, create one');
            var path = '/srcclr/v3/workspaces/'+workspaceID+'/agents'
            var data = '{"agent_type": "CLI","name": "veracode-sca-action"}'
            var createAgent = await Axios.request({
                method: 'POST',
                headers:{
                    'Authorization': auth.generateHeader(path, 'POST', API_BASE_URL, cleanedID, cleanedKEY),
                    'Content-Type': 'application/json',
                },
                data,
                 url: 'https://'+API_BASE_URL+path
            });
            var SRCCLR_API_TOKEN = createAgent.data.token.access_token
            return SRCCLR_API_TOKEN
        }
    }