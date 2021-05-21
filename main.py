# Web server
from quart import Quart, request, render_template, redirect, session
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve
# Machine learning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
# Data storage
from urllib.parse import urlparse
from psycopg2 import Error
import psycopg2 as psycopg2
import os, random
# captcha
import requests
import threading
import time
# Modified from https://towardsdatascience.com/text-classification-using-naive-bayes-theory-a-working-example-2ef4b7eb7d5a

pg_messages = urlparse(os.environ['PG_MESSAGES'])
pg_messages = psycopg2.connect(
    database = pg_messages.path[1:],
    user = pg_messages.username,
    password = pg_messages.password,
    host = pg_messages.hostname,
    port = pg_messages.port
)
pg_users = urlparse(os.environ['PG_USERS'])
pg_users = psycopg2.connect(
    database = pg_users.path[1:],
    user = pg_users.username,
    password = pg_users.password,
    host = pg_users.hostname,
    port = pg_users.port
)

model = None
modeltrained = False
def transform(string):
  return ''.join([e for e in string.lower() if e.isalnum() or e == ' '])
def update_model():
  global model, modeltrained
  model2 = make_pipeline(TfidfVectorizer(analyzer='word', token_pattern=r'\w{1,}', max_features=500), MultinomialNB(fit_prior=False))
  with pg_messages.cursor() as cursor:
    cursor.execute("SELECT * FROM messages_v2;")
    records = cursor.fetchall()
    X = [transform(record[1]) for record in records if sum(record[2:]) > 5]
    Y = [
      ['good', 'ad', 'spam'][record[2:].index(max(record[2:]))]
      for record in records if sum(record[2:]) > 5
    ]
    model2.fit(X, Y)
    model = model2
    modeltrained = True
def update_repeat():
  while True:
    try:
      update_model()
    except Exception:
      ...
    time.sleep(60)
(threading.Thread(target=update_repeat, daemon = True)).start()

app = Quart(__name__)

app.secret_key = os.environ['HCAPTCHA_SECRET']

@app.route("/")
async def hello():
    if "captcha" in session.keys() and session['captcha']:
      if 'token' in request.args.keys():
        if requests.post("https://hcaptcha.com/siteverify", data={
          "secret": os.environ['HCAPTCHA_SECRET'],
          "response": request.args['token'],
          "sitekey": "f4e77964-9555-40a4-b2c8-3bf850d8d1cf"
        }).json()['success']:
          session["captcha"] = False
        return redirect("/")
      else:
        return await render_template("captcha.html")
    if "loggedin" in session.keys() and session["loggedin"]:
      with pg_messages.cursor() as cursor:
        if 'classification' in request.args.keys():
          if 'messageid' in session.keys() and session['messageid'] != None:
            cursor.execute("SELECT * from messages_v2 WHERE id=%s;", (session['messageid'],))
            record = cursor.fetchone()
            good, ad, scam = record[2:]
            best = max(good, ad, scam)
            choice = request.args['classification']
            with pg_users.cursor() as cursor2:
              cursor2.execute("SELECT * from users WHERE uuid=%s;", (session['uuid'],))
              record = cursor2.fetchone()
              admin = record[3] == 1
              accuracy = record[1] / record[2] if not admin else 100
              if choice == 'good':
                cursor.execute("UPDATE messages_v2 SET good = %s WHERE id=%s;", (good+accuracy, session['messageid'],))
                chosen = good
                pg_messages.commit()
              if choice == 'ad':
                cursor.execute("UPDATE messages_v2 SET ad = %s WHERE id=%s;", (ad+accuracy, session['messageid'],))
                chosen = ad
                pg_messages.commit()
              if choice == 'scam':
                cursor.execute("UPDATE messages_v2 SET scam = %s WHERE id=%s;", (scam+accuracy, session['messageid'],))
                chosen = scam
                pg_messages.commit()
              session['done'] = 2 if admin else (1 if 'done' not in session.keys() else ((session['done'] + 1) % 5))
              session['captcha'] = session['done'] == 0
              cursor2.execute("UPDATE users SET accuracy = accuracy + %s, answered = answered + 1 WHERE uuid=%s;", (chosen/best, session['uuid']))
              pg_users.commit()
            session['messageid'] = None
          return redirect("/")
        if 'messageid' in session and session['messageid'] != None:
          cursor.execute("SELECT * from messages_v2 WHERE id=%s;", (session['messageid'],))
          record = cursor.fetchone()
          return await render_template("quiz.html", msg=record[1])
        with pg_users.cursor() as cursor2:
          cursor2.execute("SELECT * from users WHERE uuid=%s;", (session['uuid'],))
          record = cursor2.fetchone()
          admin = record[3] == 1
        if random.random() > .5 and not admin:
          cursor.execute("SELECT * from messages_v2 GROUP BY id HAVING SUM(good + ad + scam) > %s ORDER BY random();", (4,))
          records = cursor.fetchall()
          if len(records) > 10:
            record = records[int(len(records)*random.random())]
          else:
            cursor.execute("SELECT * from messages_v2 ORDER BY random() LIMIT 1;")
            record = cursor.fetchone()
        else:
          cursor.execute("SELECT * from messages_v2 ORDER BY random() LIMIT 1;")
          record = cursor.fetchone()
        session['messageid'] = record[0]
        return await render_template("quiz.html", msg=record[1])
    else:
      if 'token' in request.args.keys():
        resp = requests.get(f"https://mc-oauth.net/api/api?token", headers={
          'token': request.args['token']
        }).json()
        if resp['status'] == 'success' or True:
          with pg_users.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE uuid=%s", (resp['uuid'],))
            if (len(cursor.fetchall()) == 0):
              cursor.execute("INSERT INTO users (uuid) VALUES (%s);", (resp['uuid'],))
              pg_users.commit()
          session['loggedin'] = True
          session['username'] = resp['username']
          session['uuid'] = resp['uuid']
        return redirect("/")
      return await render_template("login.html")
ratelimit = time.time()
@app.route("/api", methods=["POST"])
async def json():
    global pg_messages, ratelimit
    values = await request.values
    msg = values['msg']
    lurk = False if 'lurk' not in values.keys() else values['lurk'] != '0'
    if random.random() > .95 and time.time() > ratelimit + 60 and lurk:
      ratelimit = time.time()
      with pg_messages.cursor() as cursor:
        cursor.execute("INSERT INTO messages_v2 (msg) VALUES (%s);", (msg,))
        pg_messages.commit()
    if not modeltrained:
      return "good"
    res = list(model.predict([transform(msg)]))[0]
    return res

@app.route("/ping")
async def pingpong():
    return "untrained" if not modeltrained else "trained"

if __name__ == "__main__":
    config = Config()
    config.bind = ["0.0.0.0:8080"]
    asyncio.run(serve(app, config))
