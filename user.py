from flask import Flask, request, Response
from passlib.hash import sha256_crypt
from pymongo import MongoClient
from middleware import setup_metrics
from jaeger_client import Config
from flask_opentracing import FlaskTracer
import json
import os
import logging
import bson.json_util
import random
import jwt
import prometheus_client
import opentracing

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
setup_metrics(app)

CONTENT_TYPE_LATEST = str('text/plain; version=0.0.4; charset=utf-8')

client = MongoClient('userdb', 27017)
db = client.userDb

def initialize_tracer():
  config = Config(
      config={
          'sampler': {'type': 'const', 'param': 1}
      },
      service_name='user')
  return config.initialize_tracer()

tracer = FlaskTracer(initialize_tracer)

@app.route('/register', methods=['POST'])
@tracer.trace()
def register():
  parent_span = tracer.get_span()
  logger.info("Entered User service to register")
  try:
   logger.info("Authenticating token")
   with opentracing.tracer.start_span('Token Authentication', child_of=parent_span) as span:
      token = request.headers['access-token']
      logger.debug("Received token: {}".format(token))
      jwt.decode(token, app.config['SECRET_KEY'])
      logger.info("Token authentication successful")
   with opentracing.tracer.start_span('Loading Data From Request', child_of=parent_span) as span:   
      data = json.loads(request.data)
      username = data['username']
      password = data['password']
      email = data['email']
   while True:
      try:
         logger.info('Inserting into database')
         with opentracing.tracer.start_span('Creating New User in Database', child_of=parent_span) as span:    
            userId = random.randint(1, 1000)
            userInformation = {'_id': userId, 'username': username, 'password': password, 'email': email}
            logger.debug("User details: {}".format(userInformation))
            db.user.insert(userInformation)
            response = Response(status=200)
            logger.info("Leaving User successfully.")
      except:
         userId = random.randint(1, 1000)
         continue
      break
   return response
  except:
     logger.info("Token authentication failed. Leaving user service")
     response = Response(status=500)
     return response

@app.route('/login', methods=['POST'])
@tracer.trace()
def login():
   parent_span = tracer.get_span()
   logger.info("Entered User service to login")
   try:
    logger.info("Authenticating token")
    with opentracing.tracer.start_span('Token Authentication', child_of=parent_span) as span:    
       token = request.headers['access-token']
       jwt.decode(token, app.config['SECRET_KEY'])
       logger.info("Token authentication successful")
    with opentracing.tracer.start_span('Loading Data From Request', child_of=parent_span) as span:        
       data = json.loads(request.data)
       username = data['username']
       password_candidate = data['password_candidate']
       logger.debug("Details: {}".format(data))
    try:
       logger.info("Fetching user information")
       with opentracing.tracer.start_span('Validating User', child_of=parent_span) as span:        
          userdb = db.user.find_one({'username': username})
          logger.debug("Login: {}".format(userdb))
          userInformation = db.user.find_one({'username': username})
          password = userInformation['password']
          logger.info("Validating password")
          if sha256_crypt.verify(password_candidate, password):
             logger.info("Fetching user Id {}".format(userInformation['_id']))
             userId = userInformation['_id']
             logger.debug("Type of ID: {}".format(type(userId)))
             logger.info("Dumping json")
             userId = json.dumps({"userId": userId})
             logger.info("Setting response {}".format(userId))
             response = Response(status=200, response=userId)
             logger.info("Leaving User service successfully")
          else:
             logger.warning("Passwords do not match. Leaving User Service")
             response = Response(status=401)
    except:
        logger.info("Execution failed. Leaving user service")
        response = Response(status=500)
    return response
   except:
      logger.info("Token authentication failed")
      response = Response(status=500)
      return response

@app.route('/metrics')
def metrics():
    return Response(prometheus_client.generate_latest(), mimetype=CONTENT_TYPE_LATEST)

app.run(port=5002, debug=True, host='0.0.0.0')
