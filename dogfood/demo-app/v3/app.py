"""demo-board — 사내 게시판 웹 서비스."""

from flask import Flask, jsonify, redirect, request

import auth
import db
import utils
import webhook

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    user = db.get_user_by_email(email)
    if user and auth.verify_password(user, password):
        return jsonify({"session": auth.issue_session(user)})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    return jsonify({"results": db.search_posts(keyword)})


@app.route("/posts/<int:post_id>")
def post_detail(post_id):
    return jsonify({"post": db.get_post(post_id)})


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "")
    return jsonify({"value": utils.evaluate(expression)})


@app.route("/goto")
def goto():
    return redirect(request.args.get("next"))


@app.route("/partner/status")
def partner_status():
    host = request.args.get("host", "partner.example.com")
    return jsonify(webhook.fetch_partner_status(host))


@app.route("/partner/notify", methods=["POST"])
def partner_notify():
    payload = webhook.load_notification(request.get_data())
    return jsonify({"accepted": bool(payload)})
