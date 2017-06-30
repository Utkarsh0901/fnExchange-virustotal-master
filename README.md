# fnExchange VirusTotal Plugin


<p align="center">
<img align="center" src="https://raw.githubusercontent.com/Utkarsh0901/Osquery/master/OSquery_logo.png" alt="osquery logo" width="500"/>

<p align="center">
This is a plugin for the fnExchange API router for interacting with [Virustotal](http://virustotal.com).

# 

# Installation
Simply install this as
```
$ pip install fnexchange-slack
```

# Configuration
To use this plugin with fnExchange, add the appropriate configuration to the `fnexchange.yml`
configuration file under `plugins_enabled`. A sample configuration is provided below.
Of course, note that you can use any alias instead of "slacker".

The plugin **requires** the `url` configuration.

```yaml
...
  plugins_enabled:
    ...
    slacker:
      class_name: 'fnexchange_slack.SlackPlugin'
      config:
        url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
    ...
...
```
