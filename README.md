# Intezer Labs

Publisher: Splunk  
Connector Version: 1.1.0  
Product Vendor: Intezer Labs  
Product Name: Intezer  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0

## About Intezer Splunk SOAR Connector
Intezer connector for Splunk SOAR enables security teams to automate the analysis, detection, and response of threats by integrating Intezer's technology into their Splunk workflows.

[comment]: # "File: README.md"

[comment]: # "Copyright (c) 2021-2023 Splunk Inc."

[comment]: # ""

[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"

[comment]: # "you may not use this file except in compliance with the License."

[comment]: # "You may obtain a copy of the License at"

[comment]: # ""

[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"

[comment]: # ""

[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"

[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"

[comment]: # "either express or implied. See the License for the specific language governing permissions"

[comment]: # "and limitations under the License."

[comment]: # ""

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Intezer server. Below are the
default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

### Configuration Variables

| VARIABLE   | REQUIRED | TYPE     | DESCRIPTION     |
|------------|----------|----------|-----------------|
| **apikey** | required | password | Intezer API key |

### Supported Actions

 - [test connectivity](#action-test-connectivity) - Test connection to Intezer.
 - [detonate_file](#action-detonate-file) - Analyze a file from Splunk vault with Intezer.
 - [detonate_hash](#action-detonate-hash) - Analyze a file hash (SHA1, SHA256, or MD5) with Intezer.
 - [get_file_report](#action-get-file-report) - Get a file analysis report based on an analysis ID or a file hash.
 - [detonate_url](#action-detonate-url) - Analyze a suspicious URL with Intezer.
 - [get_url_report](#action-get-url-report) - Get a URL analysis report based on a URL analysis ID.
 - [get_alert](#action-get-alert) - Get an ingested alert triage and response information using alert ID.
 - [index_file](#action-index-file) - Index the file's genes into the organizational database.
 - [unset_index_file](#action-unset-index-file) - Unset file's indexing.

## action: 'test connectivity'

Test connection to Intezer.

Type: **test**  
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

| DATA PATH    | TYPE    | CONTAINS                                         | EXAMPLE VALUES |
|--------------|---------|--------------------------------------------------|----------------|
| is_available | boolean | Whether the connection to Intezer was successful | true           |

## action: 'detonate file'

Analyze a file from Splunk vault with Intezer.

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER    | REQUIRED | DESCRIPTION     | TYPE   | CONTAINS   |
|--------------|----------|-----------------|--------|------------| 
| **vault_id** | required | File's vault ID | string | `vault id` |  

#### Action Output

| DATA PATH       | TYPE   | CONTAINS                | EXAMPLE VALUES                                       |
|-----------------|--------|-------------------------|------------------------------------------------------|
| analysis_id     | string | Intezer analysis ID     |                                                      |
| analysis_status | string | Intezer analysis status | `created` `in_progress` `queued` `failed` `finished` |
| analysis_type   | string | File Analysis           | `file`                                               |
| identifier      | string | vault id requested      | `vault id`                                           |

## action: 'detonate hash'

Analyze a file hash (SHA1, SHA256, or MD5) with Intezer.

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER     | REQUIRED | DESCRIPTION                   | TYPE   | CONTAINS                        |
|---------------|----------|-------------------------------|--------|---------------------------------| 
| **file_hash** | required | Analyze hash file via Intezer | string | `hash`  `sha256`  `sha1`  `md5` |  

#### Action Output

| DATA PATH       | TYPE   | CONTAINS                | EXAMPLE VALUES                                       |
|-----------------|--------|-------------------------|------------------------------------------------------|
| analysis_id     | string | Intezer analysis ID     |                                                      |
| analysis_status | string | Intezer analysis status | `created` `in_progress` `queued` `failed` `finished` |
| analysis_type   | string | File Analysis           | `file`                                               |
| identifier      | string | hash requested          |                                                      |

## action: 'get file report'

Get a file analysis report based on an analysis ID or a file hash.

Type: **generic**  
Read only: **True**

#### Action Parameters

Provide either analysis_id or file_hash.

| PARAMETER       | REQUIRED | DESCRIPTION                                                                                 | TYPE   | CONTAINS                        |
|-----------------|----------|---------------------------------------------------------------------------------------------|--------|---------------------------------| 
| **analysis_id** | optional | File analysis ID. The analysis ID is returned when submitting a file or a hash for analysis | string |                                 |  
| **file_hash**   | optional | Hash of the desired report                                                                  | string | `hash`  `sha256`  `sha1`  `md5` |  

#### Action Output

For more details take a look here:

- [get analysis details](https://analyze.intezer.com/api-docs.html#/paths/analyses-analysis_id/get)

- [iocs](https://analyze.intezer.com/api-docs.html#/paths/analyses-analysis_id--iocs/get)

- [dynamic ttps](https://analyze.intezer.com/api-docs.html#/paths/analyses-analysis_id--dynamic-ttps/get)

- [detect and hunt](https://analyze.intezer.com/api-docs.html#/paths/analyses-analysis_id--detect/get)

- [code reuse](https://analyze.intezer.com/api-docs.html#/paths/analyses-analysis_id--sub-analyses-root-code-reuse/get)

- [metadata](https://analyze.intezer.com/api-docs.html#/paths/analyses-analysis_id--sub-analyses-root-metadata/get)

| DATA PATH                        | TYPE       | CONTAINS                | EXAMPLE VALUES                                       |
|----------------------------------|------------|-------------------------|------------------------------------------------------|
| analysis_status                  | string     | Intezer analysis status | `created` `in_progress` `queued` `failed` `finished` |
| analysis_type                    | string     | File Analysis           | `file`                                               |
| analysis_id                      | string     | Intezer analysis ID     |                                                      | 
| analysis_content.analysis        | dictionary | analysis report         |                                                      |
| analysis_content.iocs            | dictionary | iocs report             |                                                      |
| analysis_content.ttps            | dictionary | ttps report             |                                                      |
| analysis_content.metadata        | dictionary | metadata report         |                                                      |
| analysis_content.root-code-reuse | dictionary | root-code-reuse report  |                                                      |

## action: 'detonate url'

Analyze a suspicious URL with Intezer.

Type: **investigate**  
Read only: **True**

#### Action Parameters

| PARAMETER | REQUIRED | DESCRIPTION    | TYPE   | CONTAINS    |
|-----------|----------|----------------|--------|-------------| 
| **url**   | required | URL to analyze | string | `valid url` |  

#### Action Output

| DATA PATH       | TYPE   | CONTAINS                | EXAMPLE VALUES                                       |
|-----------------|--------|-------------------------|------------------------------------------------------|
| analysis_id     | string | Intezer analysis ID     |                                                      |
| analysis_status | string | Intezer analysis status | `created` `in_progress` `queued` `failed` `finished` |
| analysis_type   | string | URL Analysis            | `url`                                                |
| identifier      | string | url requested           |                                                      |

## action: 'get url report'

Get a URL analysis report based on a URL analysis ID.

Type: **generic**  
Read only: **True**

#### Action Parameters

| PARAMETER       | REQUIRED | DESCRIPTION                                                                     | TYPE   | CONTAINS |
|-----------------|----------|---------------------------------------------------------------------------------|--------|----------| 
| **analysis_id** | required | URL analysis ID. The analysis ID is returned when submitting a URL for analysis | string |          |  

#### Action Output

For more details take a look here:

- [url-analysis-id](https://analyze.intezer.com/api-docs.html#/paths/url-analysis_id/get)

| DATA PATH                 | TYPE       | CONTAINS                | EXAMPLE VALUES                                       |
|---------------------------|------------|-------------------------|------------------------------------------------------|
| analysis_status           | string     | Intezer analysis status | `created` `in_progress` `queued` `failed` `finished` |
| analysis_type             | string     | URL Analysis            | `url`                                                |
| analysis_id               | string     | Intezer analysis ID     |                                                      |
| analysis_content.analysis | dictionary | analysis report         |                                                      |

## action: 'get alert'

Get an ingested alert triage and response information using alert ID.

Type: **generic**  
Read only: **True**

#### Action Parameters

| PARAMETER       | REQUIRED | DESCRIPTION                                                                                            | TYPE   | CONTAINS |
|-----------------|----------|--------------------------------------------------------------------------------------------------------|--------|----------| 
| **alert_id**    | required | Alert ID from the connected detection platform or as specified when the alert was submitted to Intezer | string |          |  
| **environment** | required | The environment to get the report about                                                                | string |          |  

#### Action Output

For more details take a look here:

- [get alert](https://analyze.intezer.com/api-docs.html#/paths/alerts-search/get)

## action: 'index file'

Index the file's genes into the organizational database.

Type: **correct**  
Read only: **True**

#### Action Parameters

| PARAMETER       | REQUIRED | DESCRIPTION                   | TYPE   | CONTAINS                        |
|-----------------|----------|-------------------------------|--------|---------------------------------| 
| **index_as**    | required | Index as trusted or malicious | string | `trusted`  `malicious`          |  
| **file_hash**   | optional | hash to index                 | string | `hash`  `sha256`  `sha1`  `md5` |  
| **vault_id**    | optional | File's vault ID               | string | `vault id`                      |  
| **family_name** | optional | family name to index as       | string |                                 |  

#### Action Output

| DATA PATH    | TYPE   | CONTAINS | EXAMPLE VALUES |
|--------------|--------|----------|----------------|
| **index_id** | string | Index ID |                |

## action: 'unset index file'

Unset file's indexing.

Type: **correct**  
Read only: **True**

#### Action Parameters

| PARAMETER     | REQUIRED | DESCRIPTION                     | TYPE   | CONTAINS                        |
|---------------|----------|---------------------------------|--------|---------------------------------| 
| **file_hash** | required | Hash file to unset the indexing | string | `hash`  `sha256`  `sha1`  `md5` |  

#### Action Output

No output
