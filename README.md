# Veracode Software Composition Analysis
Veracode Software Composition Analysis (agent-based scan) as a GitHub Action with the following actions:
- Run the Veracode SCA similar as the script in textual output mode
- Ability to create issues for identified vulnerabilities without creating duplicates
- Ability to run the scan on a remote repository
- Ability to run the scan with the `--quick` flag 
  
## Pull Request Decoration  
If the action runs on a pull request, it will either add a comment with the scan output to the PR or it will automatically link all created GitHub issues to the PR. This will help your review process to see if the PR can be approved or not.
  
## Inputs
:exclamation: You will need to provide `SRCCLR_API_TOKEN` as an environment variable (see examples below).  

This is only required if `workspace-autoamtion` is set to false. If workspace-automation is set to true, the workspace, project and token will be automatically generated or regenerated to run the scan. The workspace will be called `github-orgname-reponame` and the project will be called `github-orgname-reponame`.  
If `workspace-automation` is set to true the Veracode API ID and API KEY re required to be set as well.

:exclamation: If using an org-level agent, you will need to provide `SRCCLR_WORKSPACE_SLUG` as an environment variable.
  
## Artifacts  
The run will store 2 different types of artifacts.  
If `create-issues` is set to true the artifact will be the json output stored as `scaResults.json`.  
If `create-issues` is set to false the artifact will be the text output stored as `scaResults.txt`.  
For both the artifact name will be `Veracode Agent Based SCA Results`.  
  
### `github_token`

**Required** - The authorization token to allow the action to create issues.
  
If the default value `${{ github.token }}` is not working, the token must be set on the action inputs.    
You may be able to simply use `${{ secrets.GITHUB_TOKEN }}` as a default option - see __[more details](https://docs.github.com/en/actions/security-guides/automatic-token-authentication)__

Otherwise, you may be able create and assign __as secret__ a [Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) and assign it with the required permissions (`repo` scope).

  
### `workspace-automation`
**Optional** - whether to automatically create a workspace, project and token for the scan  
  
Default Value: __false__
  
### `VID`
**Optional** - only required if workspace_automation is set to true  
  
### `VKEY`
**Optional** - only required if workspace_automation is set to true
  
### `create-issues`
**Optional** - whether to create issues from found vulnerabilities

This is a boolean value attirbute

Default Value: __false__

### `url`
**Optional** - specify a remote repository URL for scanning. It will not scan the current repository in which the workflow is running

### `path`
__Optional__ - a relative path for the scan to start.
This attribute is useful in scenarios where the actual code is not in the root of the repository. An example would be mono repo where the repository is home for multiple projects

Default Value: __`.`__ (repository root folder)

### `quick`
__Optional__ - run the Veracode SCA scan with `--quick` 

Default Value: __false__

### `debug`
__Optional__ - run the Veracode SCA scan with `--debug` 

Default Value: __false__

### `skip-collectors`
__Optional__ - run the Veracode SCA scan with the `--skip-collectors` attribute with comma sporated values. 
The available values can be found here: [Scan directive](https://docs.veracode.com/r/c_sc_scan_directives) (scroll down to the `skip_collectors` directive).
Default Value: __None__

### `allow-dirty`
__Optional__ - run the Veracode SCA scan with `--allow-dirty` 

Default Value: __false__

### `recursive`
__Optional__ - run the Veracode SCA scan with `--recursive` 

Default Value: __false__ 
  
### `skip-vms`
__Optional__ - run the Veracode SCA scan with `--skip-vms`  

Default Value: __false__

### `no-graphs`
__Optional__ - do not include dependency graphs in the JSON output.

Default Value: __false__

## Examples

### Scan your repository with textual output

Run a scan but do not create issues for identified vulnerabilities.

```yaml
on: 
  schedule:
    - cron: 15 14 * * 6
  workflow_dispatch:

jobs:
  veracode-sca-task:
    runs-on: ubuntu-latest
    name: Scan repository with Veracode SCA

    steps:
      - name: Checkout
        uses: actions/checkout@v3
        
      - name: Run Veracode SCA
        env:
          SRCCLR_API_TOKEN: ${{ secrets.SRCCLR_API_TOKEN }}
        uses: veracode/veracode-sca@v2.1.9
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          create-issues: false   
```

### Scan the local repository   

Run a quick scan on the repository and create issues for all identified vulnerabilities.


```yaml
on: 
  push:
    paths-ignore:
      - "README.md"
  schedule:
    - cron: 15 14 * * 6

jobs:
  veracode-sca-task:
    runs-on: ubuntu-latest
    name: Scan repository with Veracode SCA

    steps:
      - name: Checkout
        uses: actions/checkout@v3
        
      - name: Run Veracode SCA
        env:
          SRCCLR_API_TOKEN: ${{ secrets.SRCCLR_API_TOKEN }}
        uses: veracode/veracode-sca@v2.1.9
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          quick: true
          create-issues: true 
```
## User Interface

### Issues List
<p align="center">
  <img src="/media/issues-list.png" width="700px" alt="Issues List"/>
</p>

### Individual Issue
<p align="center">
  <img src="/media/issue.png" width="700px" alt="Individual issues ticket content"/>
</p>
