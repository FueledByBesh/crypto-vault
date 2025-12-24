"""
Flask web application for CryptoVault
Web interface for using all system functions
"""

from flask import Flask, render_template, request, jsonify, send_file, session
from cryptovault.cryptovault import CryptoVault
import os
import io
import base64

app = Flask(__name__)
app.secret_key = os.urandom(32)  # For sessions

# Initialize CryptoVault
vault = CryptoVault()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    """User registration"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'})
    
    success, message = vault.register_user(username, password)
    return jsonify({'success': success, 'message': message})

@app.route('/api/login', methods=['POST'])
def login():
    """User login"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'})
    
    ip_address = request.remote_addr or "unknown"
    success, token, message = vault.login(username, password, ip_address=ip_address)
    
    if success:
        # Check if MFA is enabled
        user = vault.user_manager.get_user(username)
        if user and user.mfa_enabled:
            # MFA required - don't create session yet
            session['pending_username'] = username
            return jsonify({'success': True, 'mfa_required': True, 'message': 'MFA code required'})
        else:
            # No MFA - proceed with login
            session['username'] = username
            session['token'] = token
            return jsonify({'success': True, 'message': message, 'token': token})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/api/logout', methods=['POST'])
def logout():
    """User logout"""
    token = session.get('token')
    if token:
        vault.user_manager.logout(token)
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/check_session', methods=['GET'])
def check_session():
    """Check session"""
    token = session.get('token')
    username = session.get('username')
    
    if not token or not username:
        return jsonify({'authenticated': False})
    
    is_valid, verified_username = vault.verify_session(token)
    if is_valid and verified_username == username:
        return jsonify({'authenticated': True, 'username': username})
    else:
        session.clear()
        return jsonify({'authenticated': False})

@app.route('/api/setup_mfa', methods=['POST'])
def setup_mfa():
    """Setup MFA"""
    if not session.get('username'):
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    username = session.get('username')
    data = request.json
    password = data.get('password')
    
    success, secret, backup_codes, qr_code = vault.setup_mfa(username, password)
    
    if success:
        # Convert QR code to base64 for browser
        qr_base64 = base64.b64encode(qr_code).decode('utf-8')
        return jsonify({
            'success': True,
            'secret': secret,
            'backup_codes': backup_codes,
            'qr_code': qr_base64
        })
    else:
        return jsonify({'success': False, 'message': 'Failed to setup MFA'})

@app.route('/api/verify_mfa', methods=['POST'])
def verify_mfa():
    """Verify MFA code"""
    data = request.json
    code = data.get('code')
    
    if not code:
        return jsonify({'success': False, 'message': 'MFA code is required'})
    
    username = session.get('pending_username')
    if not username:
        return jsonify({'success': False, 'message': 'No pending MFA verification'})
    
    # Verify MFA code
    if vault.verify_mfa(username, code):
        # MFA verified - create session
        success, token, message = vault.user_manager.create_session(username)
        
        if success:
            session['username'] = username
            session['token'] = token
            session.pop('pending_username', None)
            
            # Log successful MFA login
            vault.audit_logger.log(
                event_type="mfa_login",
                username=username,
                success=True
            )
            
            return jsonify({'success': True, 'message': 'Login successful', 'token': token})
        else:
            return jsonify({'success': False, 'message': 'Session creation failed'})
    else:
        return jsonify({'success': False, 'message': 'Invalid MFA code'})

@app.route('/api/encrypt_file', methods=['POST'])
def encrypt_file():
    """File encryption"""
    if not session.get('username'):
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    username = session.get('username')
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'File not uploaded'})
    
    file = request.files['file']
    password = request.form.get('password')
    algorithm = request.form.get('algorithm', 'AES-GCM')
    
    if not password:
        return jsonify({'success': False, 'message': 'Password is required'})
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'File not selected'})
    
    input_path = None
    output_path = None
    try:
        # Save temporary file
        input_path = f"temp_{file.filename}"
        output_path = f"encrypted_{file.filename}"
        
        file.save(input_path)
        
        # Encrypt
        metadata = vault.encrypt_file(username, input_path, output_path, password, algorithm)
        
        # Send encrypted file
        response = send_file(
            output_path,
            as_attachment=True,
            download_name=output_path,
            mimetype='application/octet-stream'
        )
        
        # Delete input file after sending
        if input_path and os.path.exists(input_path):
            try:
                os.remove(input_path)
            except:
                pass
        
        return response
    except Exception as e:
        # Delete temporary files on error
        if input_path and os.path.exists(input_path):
            try:
                os.remove(input_path)
            except:
                pass
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/decrypt_file', methods=['POST'])
def decrypt_file():
    """File decryption"""
    if not session.get('username'):
        return jsonify({'success': False, 'message': 'Authentication required'})
    
    username = session.get('username')
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'File not uploaded'})
    
    file = request.files['file']
    password = request.form.get('password')
    
    if not password:
        return jsonify({'success': False, 'message': 'Password is required'})
    
    input_path = None
    output_path = None
    try:
        # Save temporary file
        input_path = f"temp_{file.filename}"
        output_path = f"decrypted_{file.filename.replace('.encrypted', '')}"
        
        file.save(input_path)
        
        # Decrypt
        result = vault.decrypt_file(username, input_path, output_path, password)
        
        if result.get('hash_verified') and result.get('hmac_verified'):
            # Send decrypted file
            response = send_file(
                output_path,
                as_attachment=True,
                download_name=output_path,
                mimetype='application/octet-stream'
            )
            
            # Delete input file after sending
            if input_path and os.path.exists(input_path):
                try:
                    os.remove(input_path)
                except:
                    pass
            
            return response
        else:
            # Delete temporary files on verification error
            if input_path and os.path.exists(input_path):
                try:
                    os.remove(input_path)
                except:
                    pass
            if output_path and os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            return jsonify({'success': False, 'message': 'File integrity verification failed'})
    except Exception as e:
        # Delete temporary files on error
        if input_path and os.path.exists(input_path):
            try:
                os.remove(input_path)
            except:
                pass
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/caesar_encrypt', methods=['POST'])
def caesar_encrypt():
    """Caesar cipher encryption"""
    try:
        data = request.json
        text = data.get('text', '')
        shift = int(data.get('shift', 0))
        
        if not text:
            return jsonify({'success': False, 'message': 'Enter text to encrypt'})
        
        if shift < 0 or shift > 25:
            return jsonify({'success': False, 'message': 'Shift must be between 0 and 25'})
        
        from cryptovault.core.caesar import CaesarCipher
        cipher = CaesarCipher(shift=shift)
        encrypted = cipher.encrypt(text)
        
        return jsonify({'success': True, 'encrypted': encrypted})
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid shift value'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/caesar_decrypt', methods=['POST'])
def caesar_decrypt():
    """Caesar cipher decryption"""
    try:
        data = request.json
        text = data.get('text', '')
        shift = int(data.get('shift', 0))
        
        if not text:
            return jsonify({'success': False, 'message': 'Enter encrypted text'})
        
        if shift < 0 or shift > 25:
            return jsonify({'success': False, 'message': 'Shift must be between 0 and 25'})
        
        from cryptovault.core.caesar import CaesarCipher
        cipher = CaesarCipher(shift=shift)
        decrypted = cipher.decrypt(text)
        
        return jsonify({'success': True, 'decrypted': decrypted})
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid shift value'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/caesar_attack', methods=['POST'])
def caesar_attack():
    """Frequency analysis attack on Caesar cipher"""
    try:
        data = request.json
        text = data.get('text', '')
        
        if not text:
            return jsonify({'success': False, 'message': 'Enter encrypted text for analysis'})
        
        if len(text) < 10:
            return jsonify({'success': False, 'message': 'Text too short for frequency analysis (minimum 10 characters)'})
        
        from cryptovault.core.caesar import FrequencyAnalyzer
        analyzer = FrequencyAnalyzer()
        results = analyzer.attack(text)
        
        # Return top-3 results
        top_results = [
            {'shift': r[0], 'text': r[1], 'score': round(r[2], 2)}
            for r in results[:3]
        ]
        
        return jsonify({'success': True, 'results': top_results})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/vigenere_encrypt', methods=['POST'])
def vigenere_encrypt():
    """Vigenere cipher encryption"""
    try:
        data = request.json
        text = data.get('text', '')
        key = data.get('key', '')
        
        if not text:
            return jsonify({'success': False, 'message': 'Enter text to encrypt'})
        
        if not key:
            return jsonify({'success': False, 'message': 'Enter encryption key'})
        
        if not key.isalpha():
            return jsonify({'success': False, 'message': 'Key must contain only letters'})
        
        from cryptovault.core.vigenere import VigenereCipher
        cipher = VigenereCipher(key=key)
        encrypted = cipher.encrypt(text)
        
        return jsonify({'success': True, 'encrypted': encrypted})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/vigenere_decrypt', methods=['POST'])
def vigenere_decrypt():
    """Vigenere cipher decryption"""
    try:
        data = request.json
        text = data.get('text', '')
        key = data.get('key', '')
        
        if not text:
            return jsonify({'success': False, 'message': 'Enter encrypted text'})
        
        if not key:
            return jsonify({'success': False, 'message': 'Enter decryption key'})
        
        if not key.isalpha():
            return jsonify({'success': False, 'message': 'Key must contain only letters'})
        
        from cryptovault.core.vigenere import VigenereCipher
        cipher = VigenereCipher(key=key)
        decrypted = cipher.decrypt(text)
        
        return jsonify({'success': True, 'decrypted': decrypted})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/blockchain_info', methods=['GET'])
def blockchain_info():
    """Blockchain information"""
    info = vault.get_blockchain_info()
    return jsonify({'success': True, 'info': info})

@app.route('/api/blockchain_logs', methods=['GET'])
def blockchain_logs():
    """Get blockchain logs"""
    logs = vault.get_blockchain_logs()
    return jsonify({'success': True, 'logs': logs})

@app.route('/api/audit_logs', methods=['GET'])
def audit_logs():
    """Get audit logs"""
    limit = int(request.args.get('limit', 50))
    logs = vault.get_recent_audit_logs(limit)
    return jsonify({'success': True, 'logs': logs})

if __name__ == '__main__':
    # Create templates folder
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5001)

