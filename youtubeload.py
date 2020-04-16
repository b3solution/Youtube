
# -*- coding: utf-8 -*-

import os

import flask
import http.client
import httplib2
import os
import random
import sys
import time
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from logging.handlers import RotatingFileHandler
import logging
logging.basicConfig(level=logging.DEBUG)
from flask import Flask
from flask import request
from apiclient.discovery import build
from apiclient.errors import HttpError
from apiclient.http import MediaFileUpload
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import argparser, run_flow

# The CLIENT_SECRETS_FILE variable specifies the name of a file that contains
# the OAuth 2.0 information for this application, including its client_id and
# client_secret.
CLIENT_SECRETS_FILE = "client_secr.json"

YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload"
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"
# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/youtube.upload']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

MISSING_CLIENT_SECRETS_MESSAGE = """
WARNING: Please configure OAuth 2.0
To make this sample run you will need to populate the client_secrets.json file
found at:
   %s
with information from the API Console
https://console.developers.google.com/
For more information about the client_secrets.json file format, please visit:
https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
""" % os.path.abspath(os.path.join(os.path.dirname("C:/Users/shiva/Downloads/client_secret.json"),
                                   CLIENT_SECRETS_FILE))

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works, but if you
# use this code in your application please replace this with a truly secret
# key. See http://flask.pocoo.org/docs/0.12/quickstart/#sessions.
app.secret_key = 'NcmV2br38vS_232JMAeQqHHW'

def get_authenticated_service(args):
  flow = flow_from_clientsecrets(CLIENT_SECRETS_FILE,
    scope=YOUTUBE_UPLOAD_SCOPE,
    message=MISSING_CLIENT_SECRETS_MESSAGE)



  storage = Storage("%s-oauth2.json" % sys.argv[0])
  credentials = storage.get()

  if credentials is None or credentials.invalid:
    credentials = run_flow(flow, storage, args)

  return build(YOUTUBE_API_SERVICE_NAME, YOUTUBE_API_VERSION,
    http=credentials.authorize(httplib2.Http()),cache_discovery=False)

def initialize_upload(youtube, options):
  tags = None
  if options.keywords:
    tags = options.keywords.split(",")

  body=dict(
    snippet=dict(
      title=options.title,
      description=options.description,
      tags=tags,
      categoryId=options.category
    ),
    status=dict(
      privacyStatus=options.privacyStatus
    )
  )

  # Call the API's videos.insert method to create and upload the video.
  insert_request = youtube.videos().insert(
    part=",".join(body.keys()),
    body=body,
    # The chunksize parameter specifies the size of each chunk of data, in
    # bytes, that will be uploaded at a time. Set a higher value for
    # reliable connections as fewer chunks lead to faster uploads. Set a lower
    # value for better recovery on less reliable connections.
    #
    # Setting "chunksize" equal to -1 in the code below means that the entire
    # file will be uploaded in a single HTTP request. (If the upload fails,
    # it will still be retried where it left off.) This is usually a best
    # practice, but if you're using Python older than 2.6 or if you're
    # running on App Engine, you should set the chunksize to something like
    # 1024 * 1024 (1 megabyte).
    media_body=MediaFileUpload(options.file, chunksize=-1, resumable=True)
  )

  resumable_upload(insert_request)

# This method implements an exponential backoff strategy to resume a
# failed upload.
def resumable_upload(insert_request):
  response = None
  error = None
  retry = 0
  while response is None:
    try:
      print ("Uploading file...")
      status, response = insert_request.next_chunk()
      if response is not None:
        if 'id' in response:
          print ("Video id '%s' was successfully uploaded." % response['id'])
        else:
          exit("The upload failed with an unexpected response: %s" % response)
    except HttpError as e:
      if e.resp.status in RETRIABLE_STATUS_CODES:
        error = "A retriable HTTP error %d occurred:\n%s" % (e.resp.status,
                                                             e.content)
      else:
        raise
    except RETRIABLE_EXCEPTIONS as e:
      error = "A retriable error occurred: %s" % e

    if error is not None:
      print (error)
      retry += 1
      if retry > MAX_RETRIES:
        exit("No longer attempting to retry.")

      max_sleep = 2 ** retry
      sleep_seconds = random.random() * max_sleep
      print ("Sleeping %f seconds and then retrying..." % sleep_seconds)
      time.sleep(sleep_seconds)
      
class Argument:
    def __init__(arg, title, description, file, category, keywords, privacyStatus, logging_level, noauth_local_webserver  ):
       arg.title = title
       arg.description = description
       arg.file = file
       arg.category = 22
       arg.keywords = ""
       arg.privacyStatus = "public"
       arg.logging_level = "DEBUG"
       arg.noauth_local_webserver = "False"
       

    
    

@app.route('/')
def index():
    if 'credentials' not in flask.session:
      return flask.redirect('authorize')

  # Load the credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

    client = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)
      
    titl = request.args.get('title')
    desc = request.args.get('description')
    fil =  request.args.get('file')
    
    args = Argument(titl,desc,fil,22,"","public","DEBUG","False")
    if not os.path.exists(args.file):
      exit("Please specify a valid file using the --file= parameter.")
    youtube = get_authenticated_service(args)
    try:
     initialize_upload(youtube, args)
     print(args.title,file=sys.stderr)
     print('Hello world!', file=sys.stderr)
    except HttpError as e:
     print ("An HTTP error %d occurred:\n%s" % (e.resp.status, e.content))
  
  #return channels_list_by_username(client,
  #  part='snippet,contentDetails,statistics',
  #  forUsername='GoogleDevelopers')


@app.route('/authorize')
def authorize():
  # Create a flow instance to manage the OAuth 2.0 Authorization Grant Flow
  # steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
  authorization_url, state = flow.authorization_url(
      # This parameter enables offline access which gives your application
      # both an access and refresh token.
      access_type='offline',
      # This parameter enables incremental auth.
      include_granted_scopes='false')

  # Store the state in the session so that the callback can verify that
  # the authorization server response.
  flask.session['state'] = state
  


  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verify the authorization server response.
  state = flask.session['state']
  app.logger.warning(state)
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  app.logger.warning(flow)    
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
  app.logger.warning(flow.redirect_uri)
  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store the credentials in the session.
  # ACTION ITEM for developers:
  #     Store user's access and refresh tokens in your data store if
  #     incorporating this code into your real app.
  credentials = flow.credentials
  flask.session['credentials'] = {
      'token': credentials.token,
      'refresh_token': credentials.refresh_token,
      'token_uri': credentials.token_uri,
      'client_id': credentials.client_id,
      'client_secret': credentials.client_secret,
      'scopes': credentials.scopes
  }

  return flask.redirect(flask.url_for('index'))

def channels_list_by_username(client, **kwargs):
  response = client.channels().list(
    **kwargs
  ).execute()

  return flask.jsonify(**response)


if __name__ == '__main__':
 
  # When running locally, disable OAuthlib's HTTPs verification. When
  # running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  app.run('localhost', 8080, debug=True)
