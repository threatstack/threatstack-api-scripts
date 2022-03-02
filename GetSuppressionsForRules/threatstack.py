#   Copyright (c) 2022 F5, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from mohawk import Sender
import requests
import time

class ApiClient:
    '''
    This class defines the Threat Stack API client object
    Its goal is to allow the user to easily make calls against the API
    '''
    def __init__(self, api_key, org_id, user_id, base_url = 'https://api.threatstack.com/v2/', timeout = 30, retry = 5):
        setattr(self, 'api_key', api_key)
        setattr(self, 'org_id', org_id)
        setattr(self, 'user_id', user_id)
        setattr(self, 'timeout', timeout)
        setattr(self, 'retry', retry)
        setattr(self, 'credentials', {
            'id': user_id,
            'key': api_key,
            'algorithm': 'sha256'
        })
        setattr(self, 'base_url', base_url)

    def get_list(self, endpoint, query_string = '', token = ''):
        '''
        This method queries a Threat Stack endpoint which returns a list of objects
        It takes a required parameter of endpoint, as well as optional parameters of
        query_string and token
        It returns an object with properties status_code, data, and token
        '''
        #Attempts tracks the number of times a request was attempted
        attempts = 1
        while True:
            #Build the full URL string
            full_url = self.base_url + endpoint + query_string

            #Append the token if it's defined
            if token:
                if query_string:
                    full_url = full_url + '&token=' + token
                else:
                    full_url = full_url + '?token=' + token

            #Get the raw output from the API
            sender = Sender(self.credentials, full_url, 'GET', always_hash_content = False, ext = self.org_id)
            resp = requests.get(full_url, headers = {'Authorization': sender.request_header}, timeout = self.timeout)

            #If a non-200 response is returned, check attempts. If it exceeds retry, throw an error. Otherwise, try the request again
            if resp.status_code != 200:
                if attempts == 1:
                    if resp.status_code != 429:
                        print("Warning: Sleeping, Threat Stack API returned a {}! (tried {} time)".format(resp.status_code, attempts))
                    else:
                        print("Back off", attempts)
                        time.sleep(2)
                else:
                    if resp.status_code != 429:
                        print("Warning: Sleeping, Threat Stack API returned a {}! (tried {} times)".format(resp.status_code, attempts))
                    else:
                        print("Back off", attempts)
                        time.sleep(2)

                if attempts == self.retry:
                    print("Error: Max retries exceeded!")
                    handle_api_error(resp.status_code, resp.text)
                else:
                    attempts += 1
            #Else, format the response object and return it
            else:
                resp_object = ListResponse(resp.status_code, resp.json())
                return resp_object

    def get_one(self, endpoint, query_string = ''):
        '''
        This method queries a Threat Stack endpoint which returns a single object
        It takes a required parameter of endpoint, as well as an optional parameter of
        query_string
        It returns an object with properties status_code and data
        '''
        
        #Attempts tracks the number of times a request was attempted
        attempts = 1
        while True:
            #Build the full URL string
            full_url = self.base_url + endpoint + query_string

            #Get the raw output from the API
            sender = Sender(self.credentials, full_url, 'GET', always_hash_content = False, ext = self.org_id)
            resp = requests.get(full_url, headers = {'Authorization': sender.request_header}, timeout = self.timeout)


            #If a non-200 response is returned, check attempts. If it exceeds retry, throw an error. Otherwise, try again

            if resp.status_code != 200:
                if attempts == 1:
                    if resp.status_code != 429 and resp.status_code !=404:
                        print("Warning: Sleeping, Threat Stack API returned a {}! (tried {} time)".format(resp.status_code, attempts))
                    elif resp.status_code == 404:
                        attempts = self.retry
                        handle_api_error(resp.status_code, resp.text)
                    else:
                        print("Back off", attempts)
                        time.sleep(30)
                        print("paused for 30")
                else:
                    if resp.status_code != 429 and resp.status_code !=404:
                        print("Warning: Sleeping, Threat Stack API returned a {}! (tried {} time)".format(resp.status_code, attempts))
                    elif resp.status_code == 404:
                        attempts = self.retry
                        handle_api_error(resp.status_code, resp.text)
                    else:
                        print("Back off", attempts)
                        time.sleep(30)
                        print("paused for 30")

                if attempts == self.retry:
                    print("Error: Max retries exceeded!")
                    handle_api_error(resp.status_code, resp.text)
                else:
                    attempts += 1

            #Else, format the response object and return it
            else:
                resp_object = OneResponse(resp.status_code, resp.json())
                return resp_object

    def post(self, endpoint, data):
        '''
        This method allows the user to make a POST request to one of Threat Stack's Write API endpoints
        It takes required parameters of endpoint and data
        '''
        #Attempts tracks the number of times a request was attempted
        attempts = 1
        while True:
            #Build the full URL string
            full_url = self.base_url + endpoint

            #Post the data to the API
            sender = Sender(self.credentials, full_url, 'POST', always_hash_content = False, ext = self.org_id, content = data, content_type = 'application/json')
            resp = requests.post(full_url, headers = {'Authorization': sender.request_header, 'Content-Type': 'application/json'}, timeout = self.timeout, data = data)

            #If a non-200 response is returned, check attempts. If it exceeds retry, throw an error. Otherwise, try again
            if resp.status_code != 200:
                if attempts == 1:
                    print("Warning: Threat Stack API returned a {}! (tried {} time)".format(resp.status_code, attempts))
                else:
                    print("Warning: Threat Stack API returned a {}! (tried {} times)".format(resp.status_code, attempts))
                if attempts == self.retry:
                    print("Error: Max retries exceeded!")
                    handle_api_error(resp.status_code, resp.text)
                else:
                    attempts += 1

            #Else, format the response object and return it
            else:
                resp_object = PostResponse(resp.status_code, resp.json())
                return resp_object

    def put(self, endpoint, data):
        '''
        This method allows the user to make a PUT request to one of Threat Stack's Write API endpoints
        It takes required parameters of endpoint and data
        '''
        #Attempts tracks the number of times a request was attempted
        attempts = 1
        while True:
            #Build the full URL string
            full_url = self.base_url + endpoint

            #Post the data to the API
            sender = Sender(self.credentials, full_url, 'PUT', always_hash_content = False, ext = self.org_id, content = data, content_type = 'application/json')
            resp = requests.put(full_url, headers = {'Authorization': sender.request_header, 'Content-Type': 'application/json'}, timeout = self.timeout, data = data)

            #If a non-200 response is returned, check attempts. If it exceeds retry, throw an error. Otherwise, try again
            if resp.status_code != 200:
                if attempts == 1:
                    print("Warning: Threat Stack API returned a {}! (tried {} time)".format(resp.status_code, attempts))
                else:
                    print("Warning: Threat Stack API returned a {}! (tried {} times)".format(resp.status_code, attempts))
                if attempts == self.retry:
                    print("Error: Max retries exceeded!")
                    handle_api_error(resp.status_code, resp.text)
                else:
                    attempts += 1

            #Else, format the response object and return it
            else:
                resp_object = PutResponse(resp.status_code, resp.json())
                return resp_object

    def delete(self, endpoint, data = None):
        '''
        This method allows the user to make a DELETE request to one of Threat Stack's Write API endpoints
        It takes a required parameter of endpoint
        '''
        #Attempts tracks the number of times a request was attempted
        attempts = 1
        while True:
            #Build the full URL string
            full_url = self.base_url + endpoint

            #Post the data to the API
            if data:
                sender = Sender(self.credentials, full_url, 'DELETE', always_hash_content = False, ext = self.org_id, content = data, content_type = 'application/json')
                resp = requests.delete(full_url, headers = {'Authorization': sender.request_header, 'Content-Type': 'application/json'}, timeout = self.timeout, data = data)
            else:
                sender = Sender(self.credentials, full_url, 'DELETE', always_hash_content = False, ext = self.org_id)
                resp = requests.delete(full_url, headers = {'Authorization': sender.request_header}, timeout = self.timeout)

            #If a non-200 response is returned, check attempts. If it exceeds retry, throw an error. Otherwise, try again
            if resp.status_code != 200:
                if attempts == 1:
                    print("Warning: Threat Stack API returned a {}! (tried {} time)".format(resp.status_code, attempts))
                else:
                    print("Warning: Threat Stack API returned a {}! (tried {} times)".format(resp.status_code, attempts))
                if attempts == self.retry:
                    print("Error: Max retries exceeded!")
                    handle_api_error(resp.status_code, resp.text)
                else:
                    attempts += 1

        #Else, format the response object
        else:
            resp_object = DeleteResponse(resp.status_code, resp.json())
            return resp_object

class Response:
    '''
    This is the parent class for the two types of responses
    It contains all of the common properties and methods between the two
    '''
    def __init__(self, status_code):
        setattr(self, 'status_code', status_code)

    def __str__(self):
        return "This is a response object from the Threat Stack API"


class ListResponse(Response):
    '''
    This class defines the object that we will return from a request for a list of objects
    Its parent is the generic "Response" class, with the following changes:
        - It has an attribute "data", set to the VALUE of a key value pair where
        the value is of type "list"
        - It has an attribute "token", which is set to the page token
    '''
    def __init__(self, status_code, data):
        #This is a child of the Response class, so call Response's init method
        Response.__init__(self, status_code)

        #A list response should take the following form:
        #{
        #    data: [list, of, data],
        #    token: (Either null or a token)
        #}

        #We expect there to only be 2 keys in the response. Raise an error if that's not the case
        if len(data) > 2:
            raise ValueError('Invalid list response from TS API: ' + str(data))

        #We're going to iterate over the object, and attempt to pull out the main data, and the token
        #If we can't find either, or if there is an unrecognized key in the response, we'll raise an error
        for key in data:
            if key == 'token':
                setattr(self, 'token', data[key])
            elif type(data[key]) is list:
                setattr(self, 'data', data[key])
            else:
                raise ValueError('Unrecognized key in response: ' + str(data[key]))

class OneResponse(Response):
    '''
    This class defines the object that we will return from a request of a single object
    Its parent is the generic Response class, with the following changes:
        - It has an attribute "data", set to the ENTIRE json response from the API
    '''
    def __init__(self, status_code, data):
        #This is a child of the Response class, so call Response's init method
        Response.__init__(self, status_code)

        #At the moment, all we're doing with this class is returning the entire data set that we see
        #We've made it its own class for the sake of consistency, and to aid in potential expansion
        setattr(self, 'data', data)



class PostResponse(Response):
    '''
    This class defines the object we will return from a POST request
    Its parent is the generic Response class, with the following changes:
        - It has an attribute "data", set to the ENTIRE json response from the API
    '''
    def __init__(self, status_code, data):
        Response.__init__(self, status_code)

        #At the moment, all we're doing with this class is returning the entire data set returned by a POST endpoint
        #We've made it its own class for the sake of consistency, and to aid in potential expansion
        setattr(self, 'data', data)

class PutResponse(Response):
    '''
    This class defines the object we will return from a PUT request
    Its parent is the generic Response class, with the following changes:
        - It has an attribute "data", set to the ENTIRE json response from the API
    '''
    def __init__(self, status_code, data):
        Response.__init__(self, status_code)

        #At the moment, all we're doing with this class is returning the entire data set returned by a PUT endpoint
        #We've made it its own class for the sake of consistency, and to aid in potential expansion
        setattr(self, 'data', data)

class DeleteResponse(Response):
    '''
    This class defines the object we will return from a DELETE request
    Its parent is the generic Response class, with the following changes:
        - It has an attribute "data", set to the ENTIRE json response from the API
    '''
    def __init__(self, status_code, data):
        Response.__init__(self, status_code)

        #At the moment, all we're doing with this class is returning the entire data set returned by a DELETE endpoint
        #We've made it its own class for the sake of consistency, and to aid in potential expansion
        setattr(self, 'data', data)

def handle_api_error(status_code, response):
    #We're going to use a dictionary mapping like a switch statement to throw the correct error
    error_switcher = {
            400: ThreatStackBadRequestError(status_code, response),
            401: ThreatStackUnauthorizedError(status_code, response),
            403: ThreatStackForbiddenError(status_code, response),
            404: ThreatStackNotFoundError(status_code, response),
            409: ThreatStackConflictError(status_code, response),
            429: ThreatStackRateLimitError(status_code, response),
            500: ThreatStackInternalError(status_code, response)
            }
    raise error_switcher.get(status_code, ThreatStackAPIError(status_code, response))

class ThreatStackAPIError(Exception):
    '''
    This is the parent class for all errors returned by the API.
    Ideally, this will never be thrown directly, but will be thrown if an otherwise unrecognized error is returned by the API
    '''
    def __init__(self, status_code, response):
        self.expression = 'Threat Stack returned a ' + str(status_code) + ' error'
        self.message = response
        super().__init__(self.expression + ': ' +  self.message)

class ThreatStackBadRequestError(ThreatStackAPIError):
    '''
    This error reflects a problem with the format of your query
    It likely means that the user has an issue with the parameters of the request
    This will be thrown if a request returns a 400 status
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)

class ThreatStackUnauthorizedError(ThreatStackAPIError):
    '''
    This error reflects a problem with authenticating against the API.
    It likely means that you've submitted your credentials incorrectly
    This will be thrown if a request returns a 401 status
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)

class ThreatStackForbiddenError(ThreatStackAPIError):
    '''
    This error reflects the user in the request not having permission to complete the desired action.
    It likely means that you submitted your credentials correctly, but the user ID you used doesn't have permission to complete the desired action
    This will be thrown if a request returns a 403 status
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)

class ThreatStackNotFoundError(ThreatStackAPIError):
    '''
    This error reflects a problem with finding the requested resource.
    It likely means a resource you requested doesn't exist, or is misnamed
    This will be thrown if a request returns a 404 status
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)

class ThreatStackConflictError(ThreatStackAPIError):
    '''
    This error reflects a problem with the request conflicting with the existing state
    This likely means you're trying to create a resource that already exists, or similar
    This will be thrown if a request returns a 409
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)

class ThreatStackRateLimitError(ThreatStackAPIError):
    '''
    This error reflects a problem with the number of requests the usre has submitted over a short period of time
    It likely means that the user has submitted too many requests
    This will be thrown if a request returns a 429 status
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)

class ThreatStackInternalError(ThreatStackAPIError):
    '''
    This error reflects an internal problem with Threat Stack itself
    It likely means that the user made a valid request, but something is broken on Threat Stack's end
    This will be thrown if a request returns a 500 error
    '''
    def __init__(self, status_code, response):
        ThreatStackAPIError.__init__(self, status_code, response)
