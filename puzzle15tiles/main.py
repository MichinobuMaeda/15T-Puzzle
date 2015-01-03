#!/usr/bin/env python
# -*- coding: utf-8 -*-#
# Copyright 2014, 2015 Michinobu Maeda.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from datetime import datetime
import base64
import hashlib
import json
import logging
import os
import re
import urllib
import urlparse

import jinja2
import webapp2
import oauth2 as oauth
from google.appengine.api import images
from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext import ndb
from webapp2_extras import sessions

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=["jinja2.ext.autoescape"],
    autoescape=True)

DEFAULT_IMAGE = "/html/numbers1.png"

webapp2_config = {
    "webapp2_extras.sessions": {
        "secret_key": "ALKSJDF ;ksjdf;k  k;AS;KDJ aldnc"
    }
}

class AuthProvider(ndb.Expando):
    pass

    @classmethod
    def get(cls, account_type):
        provider_key = ndb.Key(cls, account_type)
        e = provider_key.get()
        if e is None:
            AuthProvider(
                key=provider_key,
                consumer_key="",
                consumer_secret=""
            ).put()
            e = provider_key.get()
        return e

class Seed(ndb.Expando):
    pass

    @classmethod
    def get_key(cls):
        return ndb.Key(Seed, "seed")

    @classmethod
    def get_value(cls):
        seed_key = cls.get_key()
        e = seed_key.get()
        if e is None:
            Seed(key=seed_key, value=datetime.now().isoformat()).put()
            e = seed_key.get()
        return e.value
    
class Account(ndb.Expando):
    account_type = ndb.StringProperty()
    account_id = ndb.StringProperty()
    last_update = ndb.DateTimeProperty ()
    title = ndb.StringProperty()
    images = ndb.BlobProperty(repeated=True)
    owner = ndb.StringProperty()
    url = ndb.StringProperty()
    misc = ndb.StringProperty()

    @classmethod
    def get_key(cls, account_type, account_id):
        return base64.urlsafe_b64encode(hashlib.md5(
                Seed.get_value() + account_type + account_id
            ).digest())[:-2]

    @classmethod
    def get(cls, account_type, account_id):
        account_key = ndb.Key(
            Account, cls.get_key(account_type, account_id),
            parent=Seed.get_key()
        )
        e = account_key.get()
        
        if e is None:
            Account(
                key=account_key,
                account_type=account_type,
                account_id=account_id,
                last_update=datetime.now(),
                title="",
                owner="",
                url="",
                misc=u"{}",
            ).put()
            e = account_key.get()
        elif e.account_type != account_type:
            return None
        elif e.account_id != account_id:
            return None
            
        return e

    def get_dict(self):
        data = {}
        data["title"] = self.title
        data["owner"] = self.owner
        data["url"] = self.url
        data["image_count"] = len(self.images)
        return data

class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        self.session_store = sessions.get_store(request=self.request)
        try:
            webapp2.RequestHandler.dispatch(self)
        finally:
            self.session_store.save_sessions(self.response)
    
    def clear_session(self):
        self.session["account_type"] = ""
        self.session["status"] = "ng"
        self.session["id"] = ""
        self.session["name"] = ""
        self.session["access_token"] = ""
        self.session["access_token_secret"] = ""
        self.session["key"] = ""
    
    def get_default_template_values(self):
        template_values = {
            "err": self.session.get("err"),
            "msg": self.session.get("msg"),
            "status": self.session.get("status"),
            "id": self.session.get("id"),
            "name": self.session.get("name"),
            "type": self.session.get("account_type"),
            "key": self.session.get("key"),
            "defaultImage": DEFAULT_IMAGE
        }
        self.session["err"] = ""
        self.session["msg"] = ""
        return template_values

    def show_auth_error(self, msg):
        logging.error("%s: %s %s %s" % (
                msg,
                self.session.get("account_type"),
                self.session.get("id"),
                self.session.get("access_token"),
            ))
        self.clear_session()
        self.session["err"] = msg
        self.redirect("/")
    
    def logout(self, msg, is_error=False):
        msg = u"%s: %s %s" % (
            msg,
            self.session.get("account_type"),
            self.session.get("id"),
        )
        if is_error:
            logging.error(msg)
        else:
            logging.info(msg)
        self.clear_session()
        self.session["msg"] = u"%s。" % (msg)
        last_page = self.session.get("last_page")
        if is_error:
            self.redirect("/")
        elif last_page:
            self.redirect(last_page)
        else:
            self.redirect("/")

    def validate_account(self, key, redirect=True):
        if self.session.get("key") != key:
            if redirect:
                self.logout(u"アカウントの状態にエラーを検出したためログアウトしました", True)
                return None
            else:
                self.clear_session()
        
        account_key = ndb.Key(Account, key,parent=Seed.get_key())
        account = account_key.get()

        if account is None:
            if redirect:
                self.logout(u"アカウントが無効です", True)
            else:
                self.clear_session()
            return None
                
        misc = json.loads(account.misc)
        if misc.get("banned"):
            if redirect:
                self.logout(u"アカウントを停止しました", True)
            else:
                self.clear_session()
            return None

        update_before = datetime.now() - account.last_update
        if update_before.days > 0 or update_before.seconds > 3600:
            if redirect:
                self.logout(u"タイムアウトのため、再度ログインしてください", True)
                return None
            else:
                self.clear_session()
        return account
        
    def get_qrcode_url(self):
        return "%s?%s" % (
            "https://api.qrserver.com/v1/create-qr-code/",
            urllib.urlencode({
                    "size": "100x100",
                    "data": self.request.url,
                })
        )

    @webapp2.cached_property
    def session(self):
        return self.session_store.get_session(backend='memcache')

class BaseAuthReqHandler(BaseHandler):
    def get_provider(self, account_type):
        self.session["account_type"] = ""
        self.session["status"] = "ng"
        provider = AuthProvider.get(account_type)
        
        if provider.consumer_key == "":
            self.show_auth_error(u"工事中につきご迷惑おかけします")
            return None
        
        self.session["account_type"] = account_type
        return provider
        
class TwitterAuthReqHandler(BaseAuthReqHandler):
    def get(self):
        provider = self.get_provider("Twitter")
        if provider is None:
            return
        consumer = oauth.Consumer(provider.consumer_key, provider.consumer_secret)
        client = oauth.Client(consumer)
        resp, content = client.request(
            "https://api.twitter.com/oauth/request_token",
            "GET"
        )
        
        if resp["status"] != "200":
            self.show_auth_error(u"Twitterのアカウントへのログインが開始できませんでした")
            return
        
        request_token = dict(urlparse.parse_qsl(content))
        self.session["request_token_secret"] = request_token['oauth_token_secret']
        self.redirect("%s?oauth_token=%s" % (
                "https://api.twitter.com/oauth/authorize",
                request_token['oauth_token']
            ))

class FacebookAuthReqHandler(BaseAuthReqHandler):
    def get(self):
        provider = self.get_provider("Facebook")
        if provider is None:
            return
        self.redirect("%s?%s" % (
                "https://www.facebook.com/dialog/oauth",
                urllib.urlencode({
                        "client_id": provider.consumer_key,
                        "response_type": "token",
                        "redirect_uri": "https://puzzle15tiles.appspot.com/auth/facebook",
                })))

class GoogleAuthReqHandler(BaseAuthReqHandler):
    def get(self):
        provider = self.get_provider("Google")
        if provider is None:
            return
        self.redirect("%s?%s" % (
                "https://accounts.google.com/o/oauth2/auth",
                urllib.urlencode({
                        "client_id": provider.consumer_key,
                        "response_type": "token",
                        "scope": "profile",
                        "redirect_uri": "https://puzzle15tiles.appspot.com/auth/google",
                    })))

class GitHubAuthReqHandler(BaseAuthReqHandler):
    def get(self):
        provider = self.get_provider("GitHub")
        if provider is None:
            return
        self.redirect("%s?%s" % (
                "https://github.com/login/oauth/authorize",
                urllib.urlencode({
                        "client_id": provider.consumer_key,
                        "scope": "user",
                        "redirect_uri": "https://puzzle15tiles.appspot.com/auth/github",
                    })))

class BaseAuthHandler(BaseHandler):
    def login(self, user):
        self.session["status"] = "ok"
        self.session["id"] = str(user.get("id"))

        if user.get("displayName"):
            self.session["name"] = user.get("displayName")
        elif user.get("name"):
            self.session["name"] = user.get("name")
        elif user.get("screen_name"):
            self.session["name"] = user.get("screen_name")
        elif user.get("first_name"):
            self.session["name"] = user.get("first_name")
        elif user.get("last_name"):
            self.session["name"] = user.get("last_name")
        elif user.get("login"):
            self.session["name"] = user.get("login")
        
        self.session["key"] = Account.get_key(
            self.session.get("account_type"),
            self.session.get("id")
        )
        
        account = Account.get(
            self.session.get("account_type"),
            self.session.get("id")
        )
        account.last_update=datetime.now()
        
        if self.session.get("name"):
            if account._properties.has_key("title"):
                if account.title == "":
                    account.title = u"%s さんのパズル" % (self.session.get("name"))
            else:
                account.title = u"%s さんのパズル" % (self.session.get("name"))
        
        account.put()

        msg = u"ログインしました: %s %s" % (
            self.session.get("account_type"),
            self.session.get("name"),
        )
        logging.info(msg)
        self.redirect("/edit/%s" % (self.session.get("key")))

class TwitterAuthHandler(BaseAuthHandler):
    def get(self):
        if self.session.get("account_type") != "Twitter":
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return
        oauth_token = self.request.get("oauth_token", "")
        oauth_verifier = self.request.get("oauth_verifier", "")

        secret = self.session.get("request_token_secret")
        
        if secret is None:
            self.show_auth_error(u"ログインできませんでした")
            return
        
        token = oauth.Token(oauth_token, secret)
        token.set_verifier(oauth_verifier)

        provider = AuthProvider.get(self.session.get("account_type"))
        
        if provider.consumer_key == "":
            self.show_auth_error(u"工事中につきご迷惑おかけします")
            return
        
        consumer = oauth.Consumer(provider.consumer_key, provider.consumer_secret)
        client = oauth.Client(consumer, token)
        resp, content = client.request(
            "https://api.twitter.com/oauth/access_token",
            "POST"
        )
        
        if resp["status"] != "200":
            logging.error("status != 200")
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return

        access_token = dict(urlparse.parse_qsl(content))
        
        if access_token.get("oauth_token") is None:
            logging.error("oauth_token is None")
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return
        
        if access_token.get("oauth_token_secret") is None:
            logging.error("oauth_token_secret is None")
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return

        self.session["access_token"] = access_token.get("oauth_token")
        self.session["access_token_secret"] = access_token.get("oauth_token_secret")
        token = oauth.Token(
            access_token.get("oauth_token"),
            access_token.get("oauth_token_secret")
        )
        client = oauth.Client(consumer, token)
        resp, content = client.request(
            "https://api.twitter.com/1.1/account/verify_credentials.json",
            "GET"
        )
        
        if resp["status"] != "200":
            logging.error("status != 200")
            self.show_auth_error(u"アカウントを取得できませんでした")
            return

        self.login(json.loads(content))

class FacebookAuthHandler(BaseAuthHandler):
    def get(self):
        if self.session.get("account_type") != "Facebook":
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return
        
        if self.request.get("access_token", None) is None:
            template = JINJA_ENVIRONMENT.get_template("templates/gettoken.html")
            self.response.write(template.render({}))
            return
        
        access_token = self.request.get("access_token")
        self.session["access_token"] = access_token
        result = urlfetch.fetch("%s?%s" % (
                "https://graph.facebook.com/me",
                urllib.urlencode({
                        "access_token": access_token,
                    })))
        
        if result.status_code != 200:
            self.show_auth_error(u"アカウントを取得できませんでした")
            return
        
        self.login(json.loads(result.content))

class GoogleAuthHandler(BaseAuthHandler):
    def get(self):
        if self.session.get("account_type") != "Google":
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return

        if self.request.get("access_token", None) is None:
            template = JINJA_ENVIRONMENT.get_template("templates/gettoken.html")
            self.response.write(template.render({}))
            return

        access_token = self.request.get("access_token")
        self.session["access_token"] = access_token
        result = urlfetch.fetch("%s?%s" % (
                "https://www.googleapis.com/oauth2/v1/tokeninfo",
                urllib.urlencode({
                        "access_token": access_token,
                    })))
        
        if result.status_code != 200:
            self.show_auth_error(u"ログインできませんでした")
            return
        
        tokeninfo = json.loads(result.content)
        provider = AuthProvider.get(self.session.get("account_type"))
        
        if tokeninfo.get("audience") != provider.consumer_key:
            self.show_auth_error(u"ログインの処理中にエラーが発生しました")
            return
        
        result = urlfetch.fetch("%s?%s" % (
                "https://www.googleapis.com/plus/v1/people/me",
                urllib.urlencode({
                        "access_token": access_token,
                    })))
        
        if result.status_code != 200:
            self.show_auth_error(u"アカウントを取得できませんでした")
            return

        self.login(json.loads(result.content))

class GitHubAuthHandler(BaseAuthHandler):
    def get(self):
        if self.session.get("account_type") != "GitHub":
            self.show_auth_error(u"ログイン処理中にエラーが発生しました")
            return

        if self.request.get("code", None) is None:
            self.show_auth_error(u"ログインできませんでした")
            return

        code = self.request.get("code")
        provider = AuthProvider.get(self.session.get("account_type"))

        if provider.consumer_key == "":
            self.show_auth_error(u"工事中につきご迷惑おかけします")
            return

        result = urlfetch.fetch("%s?%s" % (
                "https://github.com/login/oauth/access_token",
                urllib.urlencode({
                        "client_id": provider.consumer_key,
                        "client_secret": provider.consumer_secret,
                        "code": code,
                        "redirect_uri": "https://puzzle15tiles.appspot.com/auth/github",
                    })))
        
        if result.status_code != 200:
            self.show_auth_error(u"ログインできませんでした")
            return

        data = dict(urlparse.parse_qsl(result.content))
        access_token = data.get("access_token")
        
        if access_token is None:
            logging.error(result.content)
            self.show_auth_error(u"ログインできませんでした")
            return

        self.session["access_token"] = access_token
        result = urlfetch.fetch("%s?%s" % (
                "https://api.github.com/user",
                urllib.urlencode({
                        "access_token": access_token,
                    })))
        
        if result.status_code != 200:
            self.show_auth_error(u"アカウントを取得できませんでした")
            return
        
        self.login(json.loads(result.content))

class TestAuthHandler(BaseAuthHandler):
    def get(self):
        if re.match("localhost", self.request.host) is None:
            self.show_auth_error(u"ログインできませんでした")
            return
        
        self.session["account_type"] = "Test"
        self.session["access_token"] = "999999999999999999999999999999"
        self.login({
                "id": "9999999999",
                "name": u"テストユーザ"
            })

class LogoutHandler(BaseHandler):
    def get(self):
        msg = u"ログアウトしました: %s %s" % (
            self.session.get("account_type"),
            self.session.get("id"),
        )
        logging.info(msg)
        self.clear_session()
        self.session["msg"] = msg
        last_page = self.session.get("last_page")
        if last_page:
            self.redirect(last_page)
        else:
            self.redirect("/")

class MainHandler(BaseHandler):
    def get(self):
        self.session["last_page"] = "/"
        if self.session.get("key"):
            self.validate_account(self.session.get("key"), redirect=False)
        template_values = self.get_default_template_values()
        template = JINJA_ENVIRONMENT.get_template("templates/index.html")
        self.response.write(template.render(template_values))

class ShowHandler(BaseHandler):
    def get(self, key):
        self.session["last_page"] = "/%s" % (key)
        account = self.validate_account(key, redirect=False)
        
        if account is None:
            self.unknown_page(key)
            return
        
        misc = json.loads(account.misc)
        if misc.get("banned"):
            self.unknown_page(key)
            return
        elif misc.get("hidden"):
            if self.session.get("status") != "ok":
                self.unknown_page(key)
                return
            
        template_values = self.get_default_template_values()
        template_values.update(account.get_dict())
        template_values["qrcode"] = self.get_qrcode_url()
        template_values["key"] = key
        template = JINJA_ENVIRONMENT.get_template("templates/show.html")
        self.response.write(template.render(template_values))
    
    def unknown_page(self, key):
        msg = u"お探しのページがありません"
        logging.error(u"%s: %s" % (msg, key,))
        self.session["msg"] = u"%s。" % (msg)
        self.redirect("/")

class EditHandler(BaseHandler):
    def get(self, key):
        account = self.validate_account(key)
        if account is None:
            return

        template_values = self.get_default_template_values()
        template_values.update(account.get_dict())
        images = []
        i = 0
        for img in account.images:
            images.append(str(i))
            i = i + 1
        template_values["images"] = images
        template = JINJA_ENVIRONMENT.get_template("templates/edit.html")
        self.response.write(template.render(template_values))

class UpdateHandler(BaseHandler):
    def post(self, item, key):
        account = self.validate_account(key)
        if account is None:
            return

        if item == "title":
            account.title = self.request.get("title", "")
        elif item == "owner":
            account.owner = self.request.get("owner", "")
        elif item == "url":
            account.url = self.request.get("url", "")
        elif item == "del-image":
            index = self.request.get("del-image", None)
            if index is None:
                pass
            else:
                i = int(index)
                if i < len(account.images):
                    account.images.pop(i)
        account.put()
        self.redirect("/edit/" + key)

class UploadHandler(BaseHandler):
    def post(self, key):
        account = self.validate_account(key)
        if account is None:
            return
        
        try:
            img = images.Image(self.request.get("image"))
            w = img.width
            h = img.height

            if w < h:
                size = (h - w) / 2.0 / h
                img.crop(left_x=0.0, top_y=size, right_x=1.0, bottom_y=(1-size))
            elif w > h:
                size = (w - h) / 2.0 / w
                img.crop(left_x=size, top_y=0.0, right_x=(1-size), bottom_y=01.0)

            img.resize(width=320, height=320)
            account.images.append(db.Blob(img.execute_transforms(output_encoding=images.JPEG, quality=100)))
            account.put()
        except images.NotImageError as ex:
            msg = u"登録する画像を指定してください。"
            self.session["msg"] = msg
            logging.warn(msg)
        except images.UnsupportedSizeError as ex:
            msg = u"サポートしていない画像サイズです。"
            self.session["msg"] = msg
            logging.warn(msg)
        except images.LargeImageError as ex:
            msg = u"画像が大きすぎます。"
            self.session["msg"] = msg
            logging.warn(msg)
        except Exception as ex:
            msg = u"画像の処理中にエラーを検出しました。"
            self.session["msg"] = msg
            logging.error(msg)
            logging.error(ex)
        self.redirect("/edit/" + key)

class ImageHandler(BaseHandler):
    def get(self, key, index):
        account_key = ndb.Key(Account, key, parent=Seed.get_key())
        account = account_key.get()
        if account is None:
            logging.error("Unknown key: " + key)
            self.error(404)
            return

        i = int(index)
        if len(account.images) <= i:
            logging.error("Unknown index: " + index)
            self.error(404)
            return
        
        self.response.headers['Content-Type'] = 'image/jpeg'
        self.response.write(account.images[i])

class ErrorMessageHandler(BaseHandler):
    def get(self):
        self.session["msg"] = self.request.get("msg", None)
        self.session["err"] = self.request.get("err", None)
        last_page = self.session.get("last_page")
        if last_page:
            self.redirect(last_page)
        else:
            self.redirect("/")

app = webapp2.WSGIApplication([
        ("/authreq/twitter", TwitterAuthReqHandler),
        ("/authreq/facebook", FacebookAuthReqHandler),
        ("/authreq/google", GoogleAuthReqHandler),
        ("/authreq/github", GitHubAuthReqHandler),
        ("/auth/twitter", TwitterAuthHandler),
        ("/auth/facebook", FacebookAuthHandler),
        ("/auth/google", GoogleAuthHandler),
        ("/auth/github", GitHubAuthHandler),
        ("/auth/test", TestAuthHandler),
        ("/logout", LogoutHandler),
        ("/", MainHandler),
        ("/([^/]+)", ShowHandler),
        ("/edit/([^/]+)", EditHandler),
        ("/update/([^/]+)/([^/]+)", UpdateHandler),
        ('/upload/([^/]+)', UploadHandler),
        ('/images/([^/]+)/([^/]+)\.jpeg', ImageHandler),
        ('/error/', ErrorMessageHandler),
], debug=True, config=webapp2_config)
