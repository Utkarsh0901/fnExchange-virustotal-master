# fnExchange VirusTotal Plugin

<p align="center">
<img align="center" src="https://raw.githubusercontent.com/Utkarsh0901/Osquery/master/OSquery_logo.png" alt="osquery logo" width="500"/>
</p>

This is a plugin for the fnExchange API router for interacting with [Virustotal](http://virustotal.com).

# Features 

# Installation
Simply install this as
```bash
$ git clone this_repo
$ cd fnExchange-virustotal-master
$ sudo pip install .
```

# Configuration
To use this plugin with fnExchange, add the appropriate configuration to the `fnexchange.yml`
configuration file under `plugins_enabled`. A sample configuration is provided below.

```yaml
...
  plugins_enabled:
    ...
    virus_total:
      class_name: 'fnexchange_virustotal.VirusTotalPlugin'
      config:
        send_urlscan: 'https://www.virustotal.com/vtapi/v2/url/scan'
        retrieve_urlscan: 'http://www.virustotal.com/vtapi/v2/url/report'
        retrieve_ipscan: 'http://www.virustotal.com/vtapi/v2/ip-address/report'
        retrieve_domainscan: 'http://www.virustotal.com/vtapi/v2/domain/report'
        posting_comments: 'https://www.virustotal.com/vtapi/v2/comments/put'
        send_filescan: 'https://www.virustotal.com/vtapi/v2/file/scan'
        send_filerescan: 'https://www.virustotal.com/vtapi/v2/file/rescan'
        retrieve_filescan: 'https://www.virustotal.com/vtapi/v2/file/report'
        apikey: 'df846364478c0808a339a76912168c76b91e078fd69f6bce326eef887675f8af'

    ...
...
```
- Get your own apikey from [here](https://virustotal.com/en/#dlg-join). 
- For reference of any funtionality refer [this](https://www.virustotal.com/en/documentation/public-api/#dlg-signin).
- We can get more function if we switch to private API, see [this](https://www.virustotal.com/en/documentation/private-api/) for more details. 