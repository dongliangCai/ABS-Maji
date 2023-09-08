from flask import Flask, json,request,jsonify
from flask_restful import Resource, Api
from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from flask_cors import CORS, cross_origin
app = Flask(__name__)
CORS(app, resources=r'/*')
data = []
group = PairingGroup('MNT159')

@app.route('/generateattributes', methods=['GET', 'POST'])
def generateAttributes():
    if request.method == 'POST':
        id = request.form.get('id')
        attriblist = request.form.get('attriblist')
        abs = ABS(group)
        ska = abs.generateattributes(id, attriblist)
        print(ska)
        return jsonify(ska)
    return "This is the index page for MathABS"

# 2. python3 MathABS.py sign "id" "attr1 attr2 attr3 ..." "message" "policy"
@app.route('/sign', methods=['Get','POST'])
def sign():
    if request.method == 'POST':
        # params = request.
        id = request.form.get('id')
        attriblist = request.form.get('attriblist')
        message = request.form.get('message')
        policy = request.form.get('policy')
        group = PairingGroup('MNT159')
        abs = ABS(group)
        signature = abs.sign(id, attriblist, message, policy)
        return jsonify(signature)
    return "this is a link for sign"

# 3. python3 MathABS.py verify "id" "signpolicy" "message" "policy"
@app.route('/verify', methods=['POST'])
def verify():
    id = request.form.get('id')
    signpolicy = request.form.get('signpolicy')
    message = request.form.get('message')
    policy = request.form.get('policy')
    abs = ABS(group)
    result = abs.verify(id, signpolicy, message, policy)
    return jsonify(result=result)

if __name__ == '__main__':
 app.run(host="0.0.0.0",debug=True)