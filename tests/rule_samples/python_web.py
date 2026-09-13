"""Static-only security regression samples; never execute this module."""

import json
import pickle
import ssl

import jwt
import requests
import yaml
from flask import redirect, render_template_string, request
from jinja2 import Template


def deserialization():
    payload = request.data
    # ruleid: dede.python.web.unsafe-deserialization
    pickle.loads(payload)
    # ok: dede.python.web.unsafe-deserialization
    json.loads(payload)


def templates():
    template = request.args.get("template")
    # ruleid: dede.python.web.template-injection
    render_template_string(template)
    # ruleid: dede.python.web.template-injection
    Template(template)
    # ok: dede.python.web.template-injection
    render_template_string("Hello {{ name }}", name=template)


def evaluation():
    code = request.form["code"]
    # ruleid: dede.python.web.code-injection
    eval(code)
    # ruleid: dede.python.web.code-injection
    exec(code)
    # ok: dede.python.web.code-injection
    eval("1 + 2")


def redirects():
    destination = request.args["next"]
    # ruleid: dede.python.web.open-redirect
    redirect(destination)
    # ok: dede.python.web.open-redirect
    redirect("/dashboard")


def xpath(document):
    name = request.values.get("name")
    query = "//user[@name='" + name + "']"
    # ruleid: dede.python.web.xpath-injection
    document.xpath(query)
    # ok: dede.python.web.xpath-injection
    document.xpath("//user[@name=$name]", name=name)


def yaml_loaders(text):
    # ruleid: dede.python.web.unsafe-yaml-loader
    yaml.load(text, Loader=yaml.Loader)
    # ruleid: dede.python.web.unsafe-yaml-loader
    yaml.unsafe_load(text)
    # ok: dede.python.web.unsafe-yaml-loader
    yaml.load(text, Loader=yaml.SafeLoader)
    # ok: dede.python.web.unsafe-yaml-loader
    yaml.safe_load(text)


def token_decoding(token, key):
    # ruleid: dede.python.web.jwt-signature-disabled
    jwt.decode(token, options={"verify_signature": False})
    # ok: dede.python.web.jwt-signature-disabled
    jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": True})


def tls_settings():
    # ruleid: dede.python.web.tls-verification-disabled
    requests.get("https://example.test", verify=False)
    # ruleid: dede.python.web.tls-verification-disabled
    ssl._create_unverified_context()
    # ok: dede.python.web.tls-verification-disabled
    requests.get("https://example.test", verify=True)
    # ok: dede.python.web.tls-verification-disabled
    ssl.create_default_context()
