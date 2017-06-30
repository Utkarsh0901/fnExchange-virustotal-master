import requests
import base64
import json
import simplejson
import urllib
import urllib2
import hashlib
from fnexchange.core.plugins import AbstractPlugin


class VirusTotalPlugin(AbstractPlugin):
	# Request for SCANNING_URL or SCANNING_IP or SCANNING_DOMAIN
	def Scan_Url(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		send_url = getattr(self.config,'send_urlscan', None)

		params = {'apikey': api_key, 'url':elements[0]['url']}
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Scan_Url" ,
			"payload": { 
		    	            "elements": [{"url":"www.virustotal.com"}],
		        	        "metadata": {}
		            	}
		}
		"""
		success = False
		info = ""
		try:
			#print "y"
			response = requests.post(send_url, data=params)
			#print response.json()
			success = response.status_code == 200
			info = "url sent"
			#print "hureee"
		except:
			pass



		return {
		'metadata': {
			'success': success,
			'info': info,
			'report_json':response.json()
		},
		'elements': elements  # return the same thing back
		}
	# Request for report of already SCANNED_URL or SCANNED_IP or SCANNED_DOMAIN
	# or SCAN_URL or SCAN_IP or SCAN_DOMAIN if not prsent in the database 
	def Retrieve_Url_Report(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		retrieve_url = getattr(self.config,'retrieve_urlscan', None)

		headers = { "Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
		params = {'apikey': api_key, 'resource':elements[0]['resource'],'scan':'1'}
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Retrieve_Url_Report" ,
			"payload": { 
							"elements": [{"resource":"www.virustotal.com"}],
							"metadata": {}
						}
		}
		"""
		success = False
		info = ""
		try:
			#print "y"
			response = requests.post(retrieve_url,params=params,headers=headers)
			#print response.json()
			success = response.status_code == 200
			info = "URL report retrieved"
			#print "hureee"
		except:
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':response.json()
			},
			'elements': elements  # return the same thing back
		}
	def Retrieve_IP_Report(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		retrieve_ip = getattr(self.config,'retrieve_ipscan', None)

		params = {'apikey': api_key, 'ip':elements[0]['ip']}
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Retrieve_IP_Report" ,
			"payload": { 
							"elements": [{"ip":"123.123.123.123"}],
							"metadata": {}
						}
		}
		"""
		success = False
		response_dict={}
		info = ""
		try:
			#print "y"
			response = urllib.urlopen('%s?%s' % (retrieve_ip, urllib.urlencode(params))).read()
			#print response.json()
			response_dict = json.loads(response)
			#print response_dict
			if response_dict:
				success = True
			info = "IP report retrieved"
			#print "hureee"
		except:
			#print "shit"
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':response_dict
			},
			'elements': elements  # return the same thing back
		}
	def Retrieve_Domain_Report(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		retrieve_domain = getattr(self.config,'retrieve_domainscan', None)

		params = {'apikey': api_key, 'domain':elements[0]['domain']}
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Retrieve_Domain_Report" ,
			"payload": { 
							"elements": [{"domain":"027.ru"}],
							"metadata": {}
						}
		}
		"""
		success = False
		response_dict = {}
		info = ""
		try:
			#print "y"
			response = urllib.urlopen('%s?%s' % (retrieve_domain, urllib.urlencode(params))).read()
			#print response.json()
			response_dict = json.loads(response)
			#print response_dict
			if response_dict:
				success = True
			info = "Domain report retrieved"
			#print "hureee"
		except:
			#print "y"
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':response_dict
			},
			'elements': elements  # return the same thing back
		}
	#POST_COMMENT on any FILES,IP,URL,DOMAIN scan reports
	def Posting_Comments(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		postcomment_url = getattr(self.config,'posting_comments', None)

		encrypted_resource = hashlib.md5()
		encrypted_resource.update(elements[0]['resource'])
		params = {
					'apikey': api_key,
					'comment': elements[0]['comment'],
					'resource': encrypted_resource.hexdigest()}
		#print encrypted_resource.hexdigest()
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Posting_Comments" ,
			"payload": { 
							"elements": [{"resource":"www.google.com","comment": "How to disinfect you from this file... #disinfect #zbot"}],
							"metadata": {}
						}
		}
		"""
		success = False
		json = {}
		info = ""
		try:
			data = urllib.urlencode(params)
			req = urllib2.Request(postcomment_url, data)
			response = urllib2.urlopen(req)
			json = response.read()
			#print response_dict
			if json:
				success = True
			info = "comment posted"
		except:
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':json
			},
			'elements': elements  # return the same thing back
		}
	def Retrieve_File_Report(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		retrieve_file = getattr(self.config,'retrieve_filescan', None)

		encrypted_resource = hashlib.md5()
		encrypted_resource.update(elements[0]['resource'])
		
		headers = { "Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
		params = {'apikey': api_key, 'resource':encrypted_resource.hexdigest()}
		
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Retrieve_File_Report" ,
			"payload": { 
							"elements": [{"resource":"www.virustotal.com"}],
							"metadata": {}
						}
		}
		"""
		success = False
		info = ""
		try:
			#print "y"
			response = requests.post(retrieve_file,params=params,headers=headers)
			#print response.json()
			success = response.status_code == 200
			info = "FILE report retrieved"
			#print "hureee"
		except:
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':response.json()
			},
			'elements': elements  # return the same thing back
		}
	def ReScan_File(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		file_rescan = getattr(self.config,'send_filerescan', None)

		encrypted_resource = hashlib.md5()
		encrypted_resource.update(elements[0]['resource'])
		
		headers = { "Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
		params = {'apikey': api_key, 'resource':encrypted_resource.hexdigest()}
		
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "ReScan_File" ,
			"payload": { 
							"elements": [{"resource":"www.virustotal.com"}],
							"metadata": {}
						}
		}
		"""
		success = False
		info = ""
		try:
			#print "y"
			response = requests.post(file_rescan,params=params,headers=headers)
			#print response.json()
			success = response.status_code == 200
			info = "FILE rescan"
			#print "hureee"
		except:
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':response.json()
			},
			'elements': elements  # return the same thing back
		}
	def Scan_File(self, payload):
		elements = payload["elements"]
		api_key = getattr(self.config, 'apikey', None)
		file_scan = getattr(self.config,'send_filescan', None)

		params = {'apikey': api_key}
		file_content = base64.b64decode(elements[0]['file_encoded'])
		files = {'file': file_content}
		"""
		{
			"alias":"virus_total",
			"token" : "SECURE-TOKEN-2-HERE" ,
			"action" : "Scan_File" ,
			"payload": { 
							"elements": [{"file_encoded":"/9j/4AAQSkZJRgABAgAAZABkAAD/7AARRHVja3kAAQAEAAAAIQAA/+4ADkFkb2JlAGTAAAAAAf/bAIQADwoKCgsKDwsLDxUODA4VGRMPDxMZHRcXFxcXHRwWGRgYGRYcHCEjJCMhHCwsLy8sLEA/Pz9AQEBAQEBAQEBAQAEQDg4QEhAUEREUFA8SDxQYExQUExgjGBgaGBgjLSAcHBwcIC0oKyQkJCsoMTEtLTExPj47Pj5AQEBAQEBAQEBA/8AAEQgAUABQAwEiAAIRAQMRAf/EAHEAAQEAAwADAAAAAAAAAAAAAAAHAwUGAQIEAQEAAAAAAAAAAAAAAAAAAAAAEAACAQIDAwgJBQAAAAAAAAABAgADBBEFBiGxBzFBYZESczQ2UXGhwUKyExR0gdEiYqIRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AKJERAREQEREBERAREQEREDDeOyWld0ODLTcqfQQpwk84f6izvMs+NtfXlSvR+g7dhsMO0CuB2DplCvvA3HdP8pks4YeZT+NU3pArUREDhOJOeZtlVxYrl9y9utVKhqBMNpBXDlHTOn0vc17vT9jc3LmrXq0g1R25SfTOK4teKy3u6u9J2GjvK+W9wu8wNzERAREQMF94G47p/lMlnDDzKfxqm9JVLxS1nXUcppuB+qmSnhiwXU4B5WoVAP8n3QK5ERAm3FrxWW93V3pOw0d5Xy3uF3mcbxaYG9y5ecUqh62X9p2mkUKaZy0HYft0PWMffA28REBERA8EY7DI0Wr6P1gajISltVYheTt0KmI/jj/AFPXLNNPqHS+Wahoql2pSvTB+lcJsdcebpHQYH1ZbneV5rQWvY3KVVYYlcQHXoZTtBmW8zLL7Gk1W8uKdCmu0l2A9nPJxc8Kc2Rz9peUKqfCX7dNsPUA49s9aHCrO6jD7i6t6S85Uu56uyu+BrNSZnV1dqREsELUz2be0UjAlcSS5HNiST6pX7O2W0tKFqm1KFNKanoRQvumm03o3K9PA1aWNe8YYNc1AMQPQi/CJv4CIiAiIgIiICIiAiIgIiIH/9k="}],
							"metadata": {}
						}
		}
		"""
		success = False
		info = ""
		try:
			#print "y"
			response = requests.post(file_scan,files=files,params=params)
			#print response.json()
			success = response.status_code == 200
			info = "FILE scan"
			#print "hureee"
		except:
			pass



		return {
			'metadata': {
				'success': success,
				'info': info,
				'report_json':response.json()
			},
			'elements': elements  # return the same thing back
		}
