"""
MEDCRYPT - Medical Report Encryption System with Data Analytics
Advanced dual-layer security + Comprehensive Analytics Dashboard
Combines: Cybersecurity + Healthcare Data Analytics + Machine Learning
"""

import os
import sys
import json
import hashlib
import getpass
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, List
import cv2
from pathlib import Path
from collections import Counter, defaultdict
import statistics

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MAGENTA = '\033[95m'


class DataAnalytics:
    """Comprehensive Data Analytics Engine for Medical and Security Data"""
    
    def __init__(self, db_path: str = "medcrypt_analytics.json"):
        self.db_path = db_path
        self.data = self.load_database()
    
    def load_database(self) -> dict:
        """Load analytics database"""
        if os.path.exists(self.db_path):
            with open(self.db_path, 'r') as f:
                return json.load(f)
        return {
            'operations': [],
            'reports': [],
            'security_events': [],
            'performance_metrics': [],
            'user_activities': [],
            'disease_statistics': {}
        }
    
    def save_database(self):
        """Save analytics database"""
        with open(self.db_path, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def log_operation(self, operation_type: str, details: dict):
        """Log operation for analytics"""
        record = {
            'timestamp': datetime.now().isoformat(),
            'type': operation_type,
            'details': details
        }
        self.data['operations'].append(record)
        self.save_database()
    
    def log_report(self, report_data: dict):
        """Store anonymized report data for medical analytics"""
        anonymized = {
            'report_id': report_data.get('report_id'),
            'age': report_data.get('age'),
            'gender': report_data.get('gender'),
            'blood_group': report_data.get('blood_group'),
            'diagnosis': report_data.get('diagnosis'),
            'symptoms': report_data.get('symptoms'),
            'department': report_data.get('department'),
            'visit_date': report_data.get('visit_date'),
            'timestamp': datetime.now().isoformat()
        }
        self.data['reports'].append(anonymized)
        
        # Update disease statistics
        diagnosis = report_data.get('diagnosis', 'Unknown')
        if diagnosis not in self.data['disease_statistics']:
            self.data['disease_statistics'][diagnosis] = 0
        self.data['disease_statistics'][diagnosis] += 1
        
        self.save_database()
    
    def log_security_event(self, event_type: str, severity: str, details: str):
        """Log security events for threat analysis"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'severity': severity,
            'details': details
        }
        self.data['security_events'].append(event)
        self.save_database()
    
    def log_performance(self, operation: str, duration: float, data_size: int):
        """Log performance metrics"""
        metric = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'duration_seconds': duration,
            'data_size_bytes': data_size,
            'throughput_mbps': (data_size / duration) / (1024 * 1024) if duration > 0 else 0
        }
        self.data['performance_metrics'].append(metric)
        self.save_database()
    
    def analyze_disease_patterns(self) -> dict:
        """Analyze disease occurrence patterns"""
        if not self.data['reports']:
            return {'error': 'No data available'}
        
        df = pd.DataFrame(self.data['reports'])
        
        analysis = {
            'total_reports': len(df),
            'disease_distribution': dict(Counter(df['diagnosis'].dropna())),
            'age_distribution': {
                'mean': df['age'].astype(str).str.extract(r'(\d+)')[0].astype(float).mean(),
                'median': df['age'].astype(str).str.extract(r'(\d+)')[0].astype(float).median(),
                'std': df['age'].astype(str).str.extract(r'(\d+)')[0].astype(float).std()
            },
            'gender_distribution': dict(Counter(df['gender'].dropna())),
            'blood_group_distribution': dict(Counter(df['blood_group'].dropna())),
            'most_common_diseases': Counter(df['diagnosis'].dropna()).most_common(5)
        }
        
        return analysis
    
    def analyze_security_threats(self) -> dict:
        """Analyze security threats and patterns"""
        if not self.data['security_events']:
            return {'error': 'No security events recorded'}
        
        df = pd.DataFrame(self.data['security_events'])
        
        analysis = {
            'total_events': len(df),
            'severity_distribution': dict(Counter(df['severity'])),
            'event_type_distribution': dict(Counter(df['type'])),
            'critical_events': len(df[df['severity'] == 'CRITICAL']),
            'recent_threats': df.tail(10).to_dict('records')
        }
        
        return analysis
    
    def analyze_performance(self) -> dict:
        """Analyze system performance metrics"""
        if not self.data['performance_metrics']:
            return {'error': 'No performance data available'}
        
        df = pd.DataFrame(self.data['performance_metrics'])
        
        analysis = {
            'total_operations': len(df),
            'encryption_stats': {
                'avg_duration': df[df['operation'] == 'encryption']['duration_seconds'].mean(),
                'total_encrypted': df[df['operation'] == 'encryption']['data_size_bytes'].sum(),
                'avg_throughput': df[df['operation'] == 'encryption']['throughput_mbps'].mean()
            },
            'steganography_stats': {
                'avg_duration': df[df['operation'] == 'steganography']['duration_seconds'].mean(),
                'total_hidden': df[df['operation'] == 'steganography']['data_size_bytes'].sum()
            },
            'overall_throughput': {
                'mean': df['throughput_mbps'].mean(),
                'max': df['throughput_mbps'].max(),
                'min': df['throughput_mbps'].min()
            }
        }
        
        return analysis
    
    def predict_disease_risk(self, age: int, gender: str, symptoms: list) -> dict:
        """Simple ML-based disease risk prediction"""
        if not self.data['reports']:
            return {'error': 'Insufficient data for prediction'}
        
        df = pd.DataFrame(self.data['reports'])
        
        # Filter similar cases
        age_range = 10
        similar_cases = df[
            (df['age'].astype(str).str.extract(r'(\d+)')[0].astype(float) >= age - age_range) &
            (df['age'].astype(str).str.extract(r'(\d+)')[0].astype(float) <= age + age_range) &
            
            (df['gender'] == gender)
        ]
        
        if len(similar_cases) == 0:
            return {'error': 'No similar cases found'}
        
        disease_counts = Counter(similar_cases['diagnosis'].dropna())
        total = sum(disease_counts.values())
        
        predictions = {
            disease: {
                'probability': count / total,
                'cases': count
            }
            for disease, count in disease_counts.most_common(5)
        }
        
        return predictions
    
    def generate_analytics_report(self) -> str:
        """Generate comprehensive analytics report"""
        report = []
        report.append("="*80)
        report.append("MEDCRYPT ANALYTICS REPORT")
        report.append("="*80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Disease Analytics
        disease_analysis = self.analyze_disease_patterns()
        if 'error' not in disease_analysis:
            report.append("1. MEDICAL DATA ANALYTICS")
            report.append("-" * 80)
            report.append(f"Total Reports Analyzed: {disease_analysis['total_reports']}")
            report.append(f"\nTop 5 Diseases:")
            for disease, count in disease_analysis['most_common_diseases']:
                report.append(f"  • {disease}: {count} cases")
            report.append(f"\nAge Statistics:")
            report.append(f"  • Mean Age: {disease_analysis['age_distribution']['mean']:.1f} years")
            report.append(f"  • Median Age: {disease_analysis['age_distribution']['median']:.1f} years")
            report.append("")
        
        # Security Analytics
        security_analysis = self.analyze_security_threats()
        if 'error' not in security_analysis:
            report.append("2. SECURITY THREAT ANALYSIS")
            report.append("-" * 80)
            report.append(f"Total Security Events: {security_analysis['total_events']}")
            report.append(f"Critical Events: {security_analysis['critical_events']}")
            report.append(f"\nEvent Distribution:")
            for event_type, count in security_analysis['event_type_distribution'].items():
                report.append(f"  • {event_type}: {count}")
            report.append("")
        
        # Performance Analytics
        perf_analysis = self.analyze_performance()
        if 'error' not in perf_analysis:
            report.append("3. PERFORMANCE METRICS")
            report.append("-" * 80)
            report.append(f"Total Operations: {perf_analysis['total_operations']}")
            if perf_analysis['encryption_stats']['avg_duration']:
                report.append(f"\nEncryption Performance:")
                report.append(f"  • Avg Duration: {perf_analysis['encryption_stats']['avg_duration']:.4f}s")
                report.append(f"  • Avg Throughput: {perf_analysis['encryption_stats']['avg_throughput']:.2f} MB/s")
            report.append("")
        
        report.append("="*80)
        
        return "\n".join(report)
    
    def export_to_csv(self, data_type: str, filename: str) -> bool:
        """Export analytics data to CSV"""
        try:
            if data_type == 'reports':
                df = pd.DataFrame(self.data['reports'])
            elif data_type == 'operations':
                df = pd.DataFrame(self.data['operations'])
            elif data_type == 'security':
                df = pd.DataFrame(self.data['security_events'])
            elif data_type == 'performance':
                df = pd.DataFrame(self.data['performance_metrics'])
            else:
                return False
            
            df.to_csv(filename, index=False)
            return True
        except Exception as e:
            print(f"Error exporting: {e}")
            return False
    
    def visualize_data(self, chart_type: str):
        """Generate visualization charts"""
        try:
            plt.style.use('seaborn-v0_8-darkgrid')
            
            if chart_type == 'disease_distribution':
                diseases = list(self.data['disease_statistics'].keys())
                counts = list(self.data['disease_statistics'].values())
                
                plt.figure(figsize=(12, 6))
                plt.bar(diseases, counts, color='steelblue')
                plt.xlabel('Disease', fontsize=12)
                plt.ylabel('Number of Cases', fontsize=12)
                plt.title('Disease Distribution Analysis', fontsize=14, fontweight='bold')
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                plt.savefig('disease_distribution.png', dpi=300)
                print(f"{Colors.GREEN}Chart saved: disease_distribution.png{Colors.END}")
                
            elif chart_type == 'performance_timeline':
                if self.data['performance_metrics']:
                    df = pd.DataFrame(self.data['performance_metrics'])
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                    
                    plt.figure(figsize=(12, 6))
                    for operation in df['operation'].unique():
                        op_data = df[df['operation'] == operation]
                        plt.plot(op_data['timestamp'], op_data['throughput_mbps'], 
                                marker='o', label=operation)
                    
                    plt.xlabel('Time', fontsize=12)
                    plt.ylabel('Throughput (MB/s)', fontsize=12)
                    plt.title('System Performance Over Time', fontsize=14, fontweight='bold')
                    plt.legend()
                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    plt.savefig('performance_timeline.png', dpi=300)
                    print(f"{Colors.GREEN}Chart saved: performance_timeline.png{Colors.END}")
            
            elif chart_type == 'security_threats':
                if self.data['security_events']:
                    df = pd.DataFrame(self.data['security_events'])
                    severity_counts = Counter(df['severity'])
                    
                    plt.figure(figsize=(10, 6))
                    colors = {'LOW': 'green', 'MEDIUM': 'orange', 'HIGH': 'red', 'CRITICAL': 'darkred'}
                    plt.pie(severity_counts.values(), labels=severity_counts.keys(), 
                           autopct='%1.1f%%', colors=[colors.get(k, 'gray') for k in severity_counts.keys()])
                    plt.title('Security Threat Severity Distribution', fontsize=14, fontweight='bold')
                    plt.tight_layout()
                    plt.savefig('security_threats.png', dpi=300)
                    print(f"{Colors.GREEN}Chart saved: security_threats.png{Colors.END}")
            
            plt.close('all')
            return True
            
        except Exception as e:
            print(f"{Colors.RED}Visualization error: {e}{Colors.END}")
            return False


class MachineLearningPredictor:
    """Machine Learning Module for Predictive Analytics"""
    
    def __init__(self, analytics: DataAnalytics):
        self.analytics = analytics
    
    def predict_breach_risk(self) -> dict:
        """Predict potential security breach risk"""
        if not self.analytics.data['security_events']:
            return {'risk_level': 'UNKNOWN', 'confidence': 0}
        
        df = pd.DataFrame(self.analytics.data['security_events'])
        
        # Calculate risk based on recent events
        recent_events = df[pd.to_datetime(df['timestamp']) > (datetime.now() - timedelta(days=7))]
        
        risk_score = 0
        if len(recent_events) > 10:
            risk_score += 30
        if len(recent_events[recent_events['severity'] == 'CRITICAL']) > 0:
            risk_score += 40
        if len(recent_events[recent_events['severity'] == 'HIGH']) > 2:
            risk_score += 20
        
        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'confidence': min(100, len(recent_events) * 10),
            'recent_events': len(recent_events),
            'recommendation': self._get_risk_recommendation(risk_level)
        }
    
    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get security recommendations based on risk level"""
        recommendations = {
            'CRITICAL': 'IMMEDIATE ACTION REQUIRED: Implement additional security measures, audit all systems, investigate recent breaches.',
            'HIGH': 'Enhanced monitoring recommended. Review access logs and increase authentication requirements.',
            'MEDIUM': 'Continue monitoring. Consider security awareness training for staff.',
            'LOW': 'System is secure. Maintain current security protocols.'
        }
        return recommendations.get(risk_level, 'Continue monitoring.')
    
    def predict_system_load(self) -> dict:
        """Predict future system load based on historical data"""
        if not self.analytics.data['operations']:
            return {'error': 'Insufficient data'}
        
        df = pd.DataFrame(self.analytics.data['operations'])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by hour
        df['hour'] = df['timestamp'].dt.hour
        hourly_load = df.groupby('hour').size()
        
        current_hour = datetime.now().hour
        next_hour = (current_hour + 1) % 24
        
        predicted_load = hourly_load.get(next_hour, hourly_load.mean())
        
        return {
            'current_hour': current_hour,
            'next_hour': next_hour,
            'predicted_operations': int(predicted_load),
            'average_hourly': int(hourly_load.mean()),
            'peak_hour': int(hourly_load.idxmax()) if len(hourly_load) > 0 else 0
        }
    
    def analyze_encryption_efficiency(self) -> dict:
        """Analyze encryption algorithm efficiency"""
        if not self.analytics.data['performance_metrics']:
            return {'error': 'No performance data'}
        
        df = pd.DataFrame(self.analytics.data['performance_metrics'])
        encryption_data = df[df['operation'] == 'encryption']
        
        if len(encryption_data) == 0:
            return {'error': 'No encryption data'}
        
        return {
            'total_encrypted': encryption_data['data_size_bytes'].sum() / (1024**2),  # MB
            'avg_speed': encryption_data['throughput_mbps'].mean(),
            'efficiency_rating': self._calculate_efficiency_rating(encryption_data['throughput_mbps'].mean()),
            'consistency': 100 - (encryption_data['throughput_mbps'].std() / encryption_data['throughput_mbps'].mean() * 100)
        }
    
    def _calculate_efficiency_rating(self, throughput: float) -> str:
        """Calculate efficiency rating"""
        if throughput > 50:
            return 'EXCELLENT'
        elif throughput > 20:
            return 'GOOD'
        elif throughput > 10:
            return 'AVERAGE'
        else:
            return 'NEEDS IMPROVEMENT'


class Logger:
    """Enhanced logging system with analytics integration"""
    
    def __init__(self, log_file: str = "medcrypt_logs.txt", analytics: DataAnalytics = None):
        self.log_file = log_file
        self.session_start = datetime.now()
        self.analytics = analytics
    
    def log(self, message: str, level: str = "INFO"):
        """Log message to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Write to file
        with open(self.log_file, 'a') as f:
            f.write(log_entry + "\n")
        
        # Log to analytics if available
        if self.analytics and level in ['ERROR', 'WARNING', 'CRITICAL']:
            severity = 'HIGH' if level == 'ERROR' else 'MEDIUM' if level == 'WARNING' else 'CRITICAL'
            self.analytics.log_security_event(level, severity, message)
        
        # Color-coded console output
        if level == "ERROR":
            print(f"{Colors.RED}{log_entry}{Colors.END}")
        elif level == "SUCCESS":
            print(f"{Colors.GREEN}{log_entry}{Colors.END}")
        elif level == "WARNING":
            print(f"{Colors.YELLOW}{log_entry}{Colors.END}")
        else:
            print(f"{Colors.CYAN}{log_entry}{Colors.END}")


class DiffieHellmanKeyExchange:
    """Implements Diffie-Hellman key exchange for secure key sharing between hospitals"""
    
    def __init__(self):
        self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.generator = 2
        self.private_key = int.from_bytes(os.urandom(32), 'big')
        self.public_key = pow(self.generator, self.private_key, self.prime)
    
    def generate_shared_secret(self, other_public_key: int) -> bytes:
        shared_secret = pow(other_public_key, self.private_key, self.prime)
        return hashlib.sha256(str(shared_secret).encode()).digest()
    
    def get_public_key_hex(self) -> str:
        return hex(self.public_key)
    
    def import_public_key(self, hex_key: str) -> int:
        return int(hex_key, 16)


class RSASignature:
    """Handles RSA digital signatures"""
    
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def sign_data(self, data: bytes) -> bytes:
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


class AESEncryption:
    """AES-256 encryption"""
    
    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def encrypt(data: str, key: bytes) -> Tuple[bytes, bytes]:
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        padded_data = data.encode()
        padding_length = 16 - (len(padded_data) % 16)
        padded_data += bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data, iv
    
    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> str:
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data.decode()
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if len(data) == 0:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy


class LSBSteganography:
    """LSB steganography"""
    
    @staticmethod
    def analyze_image_capacity(image_path: str) -> dict:
        img = cv2.imread(image_path)
        if img is None:
            return {"error": "Could not read image"}
        
        height, width, channels = img.shape
        max_bits = height * width * channels
        max_bytes = max_bits // 8
        
        return {
            "width": width,
            "height": height,
            "channels": channels,
            "max_capacity_bits": max_bits,
            "max_capacity_bytes": max_bytes,
            "max_capacity_kb": max_bytes / 1024,
            "file_size": os.path.getsize(image_path)
        }
    
    @staticmethod
    def embed_data(image_path: str, data: bytes, output_path: str) -> bool:
        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Could not read image file")
            
            binary_data = ''.join(format(byte, '08b') for byte in data)
            data_length = len(binary_data)
            
            max_bytes = img.shape[0] * img.shape[1] * 3
            if data_length > max_bytes:
                raise ValueError(f"Image too small")
            
            length_binary = format(data_length, '032b')
            binary_data = length_binary + binary_data
            
            data_index = 0
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(3):
                        if data_index < len(binary_data):
                            img[i, j, k] = (img[i, j, k] & 0xFE) | int(binary_data[data_index])
                            data_index += 1
                        else:
                            break
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
            
            cv2.imwrite(output_path, img)
            return True
            
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")
            return False
    
    @staticmethod
    def extract_data(image_path: str) -> Optional[bytes]:
        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Could not read image")
            
            binary_length = ''
            data_index = 0
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(3):
                        if data_index < 32:
                            binary_length += str(img[i, j, k] & 1)
                            data_index += 1
                        else:
                            break
                    if data_index >= 32:
                        break
                if data_index >= 32:
                    break
            
            data_length = int(binary_length, 2)
            
            binary_data = ''
            data_index = 0
            extracted = 0
            for i in range(img.shape[0]):
                for j in range(img.shape[1]):
                    for k in range(3):
                        if data_index >= 32 and extracted < data_length:
                            binary_data += str(img[i, j, k] & 1)
                            extracted += 1
                        data_index += 1
                        if extracted >= data_length:
                            break
                    if extracted >= data_length:
                        break
                if extracted >= data_length:
                    break
            
            data_bytes = bytearray()
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if len(byte) == 8:
                    data_bytes.append(int(byte, 2))
            
            return bytes(data_bytes)
            
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.END}")
            return None
    
    @staticmethod
    def calculate_psnr(original_path: str, stego_path: str) -> float:
        original = cv2.imread(original_path)
        stego = cv2.imread(stego_path)
        
        if original is None or stego is None:
            return 0.0
        
        mse = np.mean((original.astype(float) - stego.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
        return psnr


class MedicalReportManager:
    """Manages medical report data"""
    
    @staticmethod
    def create_report_interactive() -> dict:
        """Interactive report creation with user input"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}        MEDICAL REPORT DATA ENTRY{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
        
        report = {}
        
        print(f"{Colors.YELLOW}Patient Information:{Colors.END}")
        report['patient_id'] = input(f"  {Colors.GREEN}→{Colors.END} Patient ID: ").strip()
        report['patient_name'] = input(f"  {Colors.GREEN}→{Colors.END} Patient Name: ").strip()
        report['age'] = input(f"  {Colors.GREEN}→{Colors.END} Age: ").strip()
        report['gender'] = input(f"  {Colors.GREEN}→{Colors.END} Gender: ").strip()
        report['blood_group'] = input(f"  {Colors.GREEN}→{Colors.END} Blood Group: ").strip()
        report['contact'] = input(f"  {Colors.GREEN}→{Colors.END} Contact Number: ").strip()
        
        print(f"\n{Colors.YELLOW}Medical Details:{Colors.END}")
        report['diagnosis'] = input(f"  {Colors.GREEN}→{Colors.END} Diagnosis: ").strip()
        report['symptoms'] = input(f"  {Colors.GREEN}→{Colors.END} Symptoms: ").strip()
        report['test_results'] = input(f"  {Colors.GREEN}→{Colors.END} Test Results: ").strip()
        report['prescription'] = input(f"  {Colors.GREEN}→{Colors.END} Prescription: ").strip()
        
        print(f"\n{Colors.YELLOW}Doctor Information:{Colors.END}")
        report['doctor_name'] = input(f"  {Colors.GREEN}→{Colors.END} Doctor Name: ").strip()
        report['doctor_id'] = input(f"  {Colors.GREEN}→{Colors.END} Doctor ID: ").strip()
        report['specialization'] = input(f"  {Colors.GREEN}→{Colors.END} Specialization: ").strip()
        
        print(f"\n{Colors.YELLOW}Hospital Information:{Colors.END}")
        report['hospital_name'] = input(f"  {Colors.GREEN}→{Colors.END} Hospital Name: ").strip()
        report['hospital_id'] = input(f"  {Colors.GREEN}→{Colors.END} Hospital ID: ").strip()
        report['department'] = input(f"  {Colors.GREEN}→{Colors.END} Department: ").strip()
        
        print(f"\n{Colors.YELLOW}Additional Information:{Colors.END}")
        report['visit_date'] = input(f"  {Colors.GREEN}→{Colors.END} Visit Date (YYYY-MM-DD): ").strip()
        report['next_visit'] = input(f"  {Colors.GREEN}→{Colors.END} Next Visit Date: ").strip()
        report['notes'] = input(f"  {Colors.GREEN}→{Colors.END} Additional Notes: ").strip()
        report['emergency_contact'] = input(f"  {Colors.GREEN}→{Colors.END} Emergency Contact: ").strip()
        
        report['report_id'] = f"RPT{int(time.time())}"
        report['created_timestamp'] = datetime.now().isoformat()
        report['report_version'] = "1.0"
        report['encryption_status'] = "Pending"
        
        return report
    
    @staticmethod
    def display_report(report: dict):
        """Display medical report"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}        MEDICAL REPORT DETAILS{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")
        
        sections = {
            "PATIENT INFORMATION": ['patient_id', 'patient_name', 'age', 'gender', 'blood_group', 'contact'],
            "MEDICAL DETAILS": ['diagnosis', 'symptoms', 'test_results', 'prescription'],
            "DOCTOR INFORMATION": ['doctor_name', 'doctor_id', 'specialization'],
            "HOSPITAL INFORMATION": ['hospital_name', 'hospital_id', 'department'],
            "ADDITIONAL INFO": ['visit_date', 'next_visit', 'notes', 'emergency_contact', 'report_id']
        }
        
        for section, fields in sections.items():
            print(f"{Colors.YELLOW}{section}:{Colors.END}")
            for field in fields:
                if field in report:
                    label = field.replace('_', ' ').title()
                    print(f"  {Colors.GREEN}→{Colors.END} {label}: {report[field]}")
            print()


class MedCrypt:
    """Main MEDCRYPT system with analytics"""
    
    def __init__(self, password: str, logger: Logger, analytics: DataAnalytics):
        self.aes_key, self.salt = AESEncryption.generate_key(password)
        self.rsa_signature = RSASignature()
        self.dh_exchange = DiffieHellmanKeyExchange()
        self.logger = logger
        self.analytics = analytics
        self.password = password
        
        self.logger.log("MedCrypt system initialized", "SUCCESS")
        self.analytics.log_operation('system_init', {'timestamp': datetime.now().isoformat()})
    
    def encrypt_report(self, report_data: dict) -> Tuple[bytes, bytes, bytes]:
        """Encrypt medical report"""
        start_time = time.time()
        
        try:
            report_json = json.dumps(report_data, indent=2)
            self.logger.log(f"Report size: {len(report_json)} bytes", "INFO")
            
            encrypted_data, iv = AESEncryption.encrypt(report_json, self.aes_key)
            self.logger.log(f"Data encrypted: {len(encrypted_data)} bytes", "SUCCESS")
            
            entropy = AESEncryption.calculate_entropy(encrypted_data)
            self.logger.log(f"Encryption entropy: {entropy:.4f} bits/byte", "INFO")
            
            signature = self.rsa_signature.sign_data(encrypted_data)
            self.logger.log(f"Digital signature created: {len(signature)} bytes", "SUCCESS")
            
            duration = time.time() - start_time
            self.analytics.log_performance('encryption', duration, len(encrypted_data))
            self.analytics.log_operation('encryption', {
                'size': len(encrypted_data),
                'duration': duration,
                'entropy': entropy
            })
            
            return encrypted_data, iv, signature
            
        except Exception as e:
            self.logger.log(f"Encryption failed: {e}", "ERROR")
            raise
    
    def hide_in_image(self, encrypted_data: bytes, iv: bytes, signature: bytes,
                      image_path: str, output_path: str) -> bool:
        """Hide encrypted report in image"""
        start_time = time.time()
        
        try:
            capacity = LSBSteganography.analyze_image_capacity(image_path)
            self.logger.log(f"Image capacity: {capacity['max_capacity_kb']:.2f} KB", "INFO")
            
            package = {
                'encrypted_data': encrypted_data.hex(),
                'iv': iv.hex(),
                'signature': signature.hex(),
                'salt': self.salt.hex(),
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'algorithm': 'AES-256-CBC'
            }
            
            package_bytes = json.dumps(package).encode()
            self.logger.log(f"Package size: {len(package_bytes)} bytes", "INFO")
            
            if len(package_bytes) > capacity['max_capacity_bytes']:
                self.logger.log("Image capacity insufficient", "ERROR")
                return False
            
            success = LSBSteganography.embed_data(image_path, package_bytes, output_path)
            
            if success:
                psnr = LSBSteganography.calculate_psnr(image_path, output_path)
                self.logger.log(f"Data hidden. PSNR: {psnr:.2f} dB", "SUCCESS")
                
                duration = time.time() - start_time
                self.analytics.log_performance('steganography', duration, len(package_bytes))
                self.analytics.log_operation('steganography', {
                    'size': len(package_bytes),
                    'psnr': psnr,
                    'duration': duration
                })
            
            return success
            
        except Exception as e:
            self.logger.log(f"Steganography failed: {e}", "ERROR")
            return False
    
    def extract_and_decrypt(self, stego_image_path: str, password: str) -> Optional[dict]:
        """Extract and decrypt report"""
        start_time = time.time()
        
        try:
            self.logger.log("Starting extraction...", "INFO")
            
            package_bytes = LSBSteganography.extract_data(stego_image_path)
            if package_bytes is None:
                self.logger.log("No hidden data found", "ERROR")
                return None
            
            self.logger.log(f"Extracted {len(package_bytes)} bytes", "SUCCESS")
            
            package = json.loads(package_bytes.decode())
            
            encrypted_data = bytes.fromhex(package['encrypted_data'])
            iv = bytes.fromhex(package['iv'])
            signature = bytes.fromhex(package['signature'])
            salt = bytes.fromhex(package['salt'])
            
            self.logger.log("Verifying signature...", "INFO")
            if not self.rsa_signature.verify_signature(encrypted_data, signature):
                self.logger.log("SIGNATURE VERIFICATION FAILED!", "ERROR")
                self.analytics.log_security_event('signature_failure', 'CRITICAL', 'Data tampering detected')
                return None
            
            self.logger.log("Signature verified", "SUCCESS")
            
            key, _ = AESEncryption.generate_key(password, salt)
            
            self.logger.log("Decrypting data...", "INFO")
            decrypted_json = AESEncryption.decrypt(encrypted_data, key, iv)
            report_data = json.loads(decrypted_json)
            
            self.logger.log("Report decrypted successfully", "SUCCESS")
            
            duration = time.time() - start_time
            self.analytics.log_operation('decryption', {'duration': duration})
            
            return report_data
            
        except Exception as e:
            self.logger.log(f"Extraction failed: {e}", "ERROR")
            self.analytics.log_security_event('decryption_failure', 'HIGH', str(e))
            return None


class MedCryptCLI:
    """Command-Line Interface with Full Analytics"""
    
    def __init__(self):
        self.analytics = DataAnalytics()
        self.logger = Logger(analytics=self.analytics)
        self.ml_predictor = None
        self.medcrypt = None
        self.current_report = None
        self.report_manager = MedicalReportManager()
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        banner = f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║                     MEDCRYPT v2.0 - ANALYTICS EDITION               ║
║         Medical Report Encryption + Data Analytics System            ║
║                                                                      ║
║      🔒 Cybersecurity + 📊 Data Analytics + 🤖 Machine Learning      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
    
    def print_menu(self):
        menu = f"""
{Colors.BOLD}{Colors.YELLOW}╔═══════════════════ MAIN MENU ════════════════════╗{Colors.END}
{Colors.YELLOW}║                                                   ║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.CYAN}🔐 SECURITY OPERATIONS{Colors.END}                        {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}1.{Colors.END}  Initialize System                         {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}2.{Colors.END}  Create Medical Report                     {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}3.{Colors.END}  Encrypt Report                            {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}4.{Colors.END}  Hide Report in Image                      {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}5.{Colors.END}  Extract & Decrypt Report                  {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}6.{Colors.END}  Complete Workflow                         {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║                                                   ║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.CYAN}📊 DATA ANALYTICS{Colors.END}                             {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}7.{Colors.END}  Disease Pattern Analysis                  {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}8.{Colors.END}  Security Threat Analysis                  {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}9.{Colors.END}  Performance Analytics                     {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}10.{Colors.END} Generate Analytics Report                 {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}11.{Colors.END} Visualize Data (Charts)                   {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}12.{Colors.END} Export Data to CSV                        {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║                                                   ║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.CYAN}🤖 MACHINE LEARNING{Colors.END}                           {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}13.{Colors.END} Predict Disease Risk                      {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}14.{Colors.END} Predict Security Breach Risk              {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}15.{Colors.END} System Load Prediction                    {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}16.{Colors.END} Encryption Efficiency Analysis            {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║                                                   ║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.CYAN}⚙️  UTILITIES{Colors.END}                                  {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}17.{Colors.END} Analyze Image Capacity                    {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}18.{Colors.END} View Current Report                       {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}19.{Colors.END} Load/Save Report                          {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.GREEN}20.{Colors.END} View System Info                          {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║{Colors.END}  {Colors.RED}0.{Colors.END}  Exit                                      {Colors.YELLOW}║{Colors.END}
{Colors.YELLOW}║                                                   ║{Colors.END}
{Colors.BOLD}{Colors.YELLOW}╚═══════════════════════════════════════════════════╝{Colors.END}
        """
        print(menu)
    
    def initialize_system(self):
        """Initialize system with password"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}System Initialization{Colors.END}")
        print("=" * 70)
        
        password = input(f"{Colors.GREEN}Enter master password: {Colors.END}")
        confirm = input(f"{Colors.GREEN}Confirm password: {Colors.END}")
        
        if password != confirm:
            print(f"{Colors.RED}Passwords do not match!{Colors.END}")
            time.sleep(2)
            return
        
        if len(password) < 8:
            print(f"{Colors.RED}Password must be at least 8 characters!{Colors.END}")
            time.sleep(2)
            return
        
        self.medcrypt = MedCrypt(password, self.logger, self.analytics)
        self.ml_predictor = MachineLearningPredictor(self.analytics)
        
        print(f"\n{Colors.GREEN}✓ System initialized successfully!{Colors.END}")
        time.sleep(2)
    
    def create_report(self):
        """Create medical report"""
        if self.medcrypt is None:
            print(f"{Colors.RED}Please initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        self.current_report = self.report_manager.create_report_interactive()
        self.analytics.log_report(self.current_report)
        
        print(f"\n{Colors.GREEN}✓ Report created and logged to analytics!{Colors.END}")
        print(f"{Colors.CYAN}Report ID: {self.current_report['report_id']}{Colors.END}")
        time.sleep(2)
    
    def encrypt_report(self):
        """Encrypt report"""
        if self.medcrypt is None or self.current_report is None:
            print(f"{Colors.RED}Initialize system and create report first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}Encrypting report...{Colors.END}")
        
        self.encrypted_data, self.iv, self.signature = self.medcrypt.encrypt_report(self.current_report)
        
        print(f"\n{Colors.GREEN}✓ Encryption successful!{Colors.END}")
        print(f"{Colors.CYAN}Encrypted: {len(self.encrypted_data)} bytes{Colors.END}")
        time.sleep(2)
    
    def hide_in_image(self):
        """Hide in image"""
        if not hasattr(self, 'encrypted_data'):
            print(f"{Colors.RED}Encrypt a report first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}Hide Report in Medical Image{Colors.END}")
        print("=" * 70)
        
        image_path = input(f"{Colors.GREEN}Input image path: {Colors.END}").strip()
        if not os.path.exists(image_path):
            print(f"{Colors.RED}File not found!{Colors.END}")
            time.sleep(2)
            return
        
        output_path = input(f"{Colors.GREEN}Output stego image path: {Colors.END}").strip()
        
        success = self.medcrypt.hide_in_image(self.encrypted_data, self.iv, self.signature, image_path, output_path)
        
        if success:
            print(f"\n{Colors.GREEN}✓ Data hidden successfully!{Colors.END}")
        time.sleep(2)
    
    def extract_decrypt(self):
        """Extract and decrypt"""
        if self.medcrypt is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}Extract & Decrypt{Colors.END}")
        print("=" * 70)
        
        stego_path = input(f"{Colors.GREEN}Stego image path: {Colors.END}").strip()
        if not os.path.exists(stego_path):
            print(f"{Colors.RED}File not found!{Colors.END}")
            time.sleep(2)
            return
        
        password = input(f"{Colors.GREEN}Password: {Colors.END}")
        
        recovered = self.medcrypt.extract_and_decrypt(stego_path, password)
        
        if recovered:
            print(f"\n{Colors.GREEN}✓ Report recovered!{Colors.END}\n")
            self.report_manager.display_report(recovered)
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def complete_workflow(self):
        """Complete workflow"""
        if self.medcrypt is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}Complete Workflow{Colors.END}")
        print("=" * 70)
        
        choice = input(f"{Colors.GREEN}Use existing report? (y/n): {Colors.END}").lower()
        if choice != 'y' or self.current_report is None:
            self.current_report = self.report_manager.create_report_interactive()
            self.analytics.log_report(self.current_report)
        
        print(f"\n{Colors.YELLOW}Encrypting...{Colors.END}")
        self.encrypted_data, self.iv, self.signature = self.medcrypt.encrypt_report(self.current_report)
        print(f"{Colors.GREEN}✓ Encrypted{Colors.END}")
        
        image_path = input(f"\n{Colors.GREEN}Input image: {Colors.END}").strip()
        if not os.path.exists(image_path):
            print(f"{Colors.RED}File not found!{Colors.END}")
            time.sleep(2)
            return
        
        output_path = input(f"{Colors.GREEN}Output stego image: {Colors.END}").strip()
        
        success = self.medcrypt.hide_in_image(self.encrypted_data, self.iv, self.signature, image_path, output_path)
        
        if success:
            print(f"\n{Colors.GREEN}{'='*70}{Colors.END}")
            print(f"{Colors.GREEN}✓ WORKFLOW COMPLETE!{Colors.END}")
            print(f"{Colors.GREEN}{'='*70}{Colors.END}")
        
        time.sleep(3)
    
    def disease_analysis(self):
        """Disease pattern analysis"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}Disease Pattern Analysis{Colors.END}")
        print("=" * 70)
        
        analysis = self.analytics.analyze_disease_patterns()
        
        if 'error' in analysis:
            print(f"{Colors.YELLOW}{analysis['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Total Reports: {analysis['total_reports']}{Colors.END}")
            print(f"\n{Colors.YELLOW}Top 5 Diseases:{Colors.END}")
            for disease, count in analysis['most_common_diseases']:
                print(f"  • {disease}: {count} cases")
            
            print(f"\n{Colors.YELLOW}Age Statistics:{Colors.END}")
            print(f"  Mean: {analysis['age_distribution']['mean']:.1f} years")
            print(f"  Median: {analysis['age_distribution']['median']:.1f} years")
            
            print(f"\n{Colors.YELLOW}Gender Distribution:{Colors.END}")
            for gender, count in analysis['gender_distribution'].items():
                print(f"  • {gender}: {count}")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def security_analysis(self):
        """Security threat analysis"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}Security Threat Analysis{Colors.END}")
        print("=" * 70)
        
        analysis = self.analytics.analyze_security_threats()
        
        if 'error' in analysis:
            print(f"{Colors.YELLOW}{analysis['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Total Events: {analysis['total_events']}{Colors.END}")
            print(f"{Colors.RED}Critical Events: {analysis['critical_events']}{Colors.END}")
            
            print(f"\n{Colors.YELLOW}Severity Distribution:{Colors.END}")
            for severity, count in analysis['severity_distribution'].items():
                print(f"  • {severity}: {count}")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def performance_analysis(self):
        """Performance analytics"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}Performance Analytics{Colors.END}")
        print("=" * 70)
        
        analysis = self.analytics.analyze_performance()
        
        if 'error' in analysis:
            print(f"{Colors.YELLOW}{analysis['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Total Operations: {analysis['total_operations']}{Colors.END}")
            
            if analysis['encryption_stats']['avg_duration']:
                print(f"\n{Colors.YELLOW}Encryption Performance:{Colors.END}")
                print(f"  Avg Duration: {analysis['encryption_stats']['avg_duration']:.4f}s")
                print(f"  Avg Throughput: {analysis['encryption_stats']['avg_throughput']:.2f} MB/s")
            
            print(f"\n{Colors.YELLOW}Overall Throughput:{Colors.END}")
            print(f"  Mean: {analysis['overall_throughput']['mean']:.2f} MB/s")
            print(f"  Max: {analysis['overall_throughput']['max']:.2f} MB/s")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def generate_report(self):
        """Generate analytics report"""
        print(f"\n{Colors.CYAN}Generating comprehensive report...{Colors.END}")
        
        report = self.analytics.generate_analytics_report()
        print(report)
        
        save = input(f"\n{Colors.GREEN}Save to file? (y/n): {Colors.END}").lower()
        if save == 'y':
            filename = input(f"{Colors.GREEN}Filename: {Colors.END}").strip()
            with open(filename, 'w') as f:
                f.write(report)
            print(f"{Colors.GREEN}✓ Saved to {filename}{Colors.END}")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def visualize_data(self):
        """Visualize data"""
        print(f"\n{Colors.CYAN}Data Visualization{Colors.END}")
        print("=" * 70)
        print(f"{Colors.YELLOW}1. Disease Distribution")
        print(f"2. Performance Timeline")
        print(f"3. Security Threats{Colors.END}")
        
        choice = input(f"\n{Colors.GREEN}Select chart: {Colors.END}").strip()
        
        chart_map = {
            '1': 'disease_distribution',
            '2': 'performance_timeline',
            '3': 'security_threats'
        }
        
        if choice in chart_map:
            self.analytics.visualize_data(chart_map[choice])
        
        time.sleep(2)
    
    def export_csv(self):
        """Export to CSV"""
        print(f"\n{Colors.CYAN}Export Data to CSV{Colors.END}")
        print("=" * 70)
        print(f"{Colors.YELLOW}1. Reports")
        print(f"2. Operations")
        print(f"3. Security Events")
        print(f"4. Performance{Colors.END}")
        
        choice = input(f"\n{Colors.GREEN}Select: {Colors.END}").strip()
        
        data_map = {'1': 'reports', '2': 'operations', '3': 'security', '4': 'performance'}
        
        if choice in data_map:
            filename = input(f"{Colors.GREEN}Filename: {Colors.END}").strip()
            if self.analytics.export_to_csv(data_map[choice], filename):
                print(f"{Colors.GREEN}✓ Exported to {filename}{Colors.END}")
        
        time.sleep(2)
    
    def predict_disease(self):
        """Predict disease risk"""
        if self.ml_predictor is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}Disease Risk Prediction{Colors.END}")
        print("=" * 70)
        
        age = int(input(f"{Colors.GREEN}Age: {Colors.END}"))
        gender = input(f"{Colors.GREEN}Gender: {Colors.END}").strip()
        
        predictions = self.analytics.predict_disease_risk(age, gender, [])
        
        if 'error' in predictions:
            print(f"{Colors.YELLOW}{predictions['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Risk Predictions:{Colors.END}")
            for disease, data in predictions.items():
                print(f"  • {disease}: {data['probability']*100:.1f}% ({data['cases']} cases)")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def predict_breach(self):
        """Predict breach risk"""
        if self.ml_predictor is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}Security Breach Risk Prediction{Colors.END}")
        print("=" * 70)
        
        prediction = self.ml_predictor.predict_breach_risk()
        
        risk_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN
        }
        
        color = risk_colors.get(prediction['risk_level'], Colors.CYAN)
        
        print(f"\n{color}Risk Level: {prediction['risk_level']}{Colors.END}")
        print(f"Risk Score: {prediction['risk_score']}/100")
        print(f"Confidence: {prediction['confidence']}%")
        print(f"Recent Events: {prediction['recent_events']}")
        print(f"\n{Colors.YELLOW}Recommendation:{Colors.END}")
        print(f"  {prediction['recommendation']}")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def predict_load(self):
        """Predict system load"""
        if self.ml_predictor is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}System Load Prediction{Colors.END}")
        print("=" * 70)
        
        prediction = self.ml_predictor.predict_system_load()
        
        if 'error' in prediction:
            print(f"{Colors.YELLOW}{prediction['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Load Forecast:{Colors.END}")
            print(f"  Current Hour: {prediction['current_hour']}:00")
            print(f"  Next Hour: {prediction['next_hour']}:00")
            print(f"  Predicted Operations: {prediction['predicted_operations']}")
            print(f"  Average Hourly: {prediction['average_hourly']}")
            print(f"  Peak Hour: {prediction['peak_hour']}:00")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def encryption_efficiency(self):
        """Encryption efficiency analysis"""
        if self.ml_predictor is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.CYAN}Encryption Efficiency Analysis{Colors.END}")
        print("=" * 70)
        
        analysis = self.ml_predictor.analyze_encryption_efficiency()
        
        if 'error' in analysis:
            print(f"{Colors.YELLOW}{analysis['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Efficiency Metrics:{Colors.END}")
            print(f"  Total Encrypted: {analysis['total_encrypted']:.2f} MB")
            print(f"  Average Speed: {analysis['avg_speed']:.2f} MB/s")
            print(f"  Efficiency Rating: {analysis['efficiency_rating']}")
            print(f"  Consistency: {analysis['consistency']:.2f}%")
        
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def analyze_image(self):
        """Analyze image capacity"""
        print(f"\n{Colors.CYAN}Image Capacity Analysis{Colors.END}")
        print("=" * 70)
        
        image_path = input(f"{Colors.GREEN}Image path: {Colors.END}").strip()
        
        if not os.path.exists(image_path):
            print(f"{Colors.RED}File not found!{Colors.END}")
            time.sleep(2)
            return
        
        capacity = LSBSteganography.analyze_image_capacity(image_path)
        
        if 'error' in capacity:
            print(f"{Colors.RED}{capacity['error']}{Colors.END}")
        else:
            print(f"\n{Colors.YELLOW}Image Properties:{Colors.END}")
            print(f"  Dimensions: {capacity['width']} x {capacity['height']}")
            print(f"  Channels: {capacity['channels']}")
            print(f"  File Size: {capacity['file_size']/1024:.2f} KB")
            print(f"\n{Colors.YELLOW}Steganography Capacity:{Colors.END}")
            print(f"  Maximum: {capacity['max_capacity_kb']:.2f} KB")
            print(f"  Maximum: {capacity['max_capacity_bytes']} bytes")
        
        time.sleep(3)
    
    def view_report(self):
        """View current report"""
        if self.current_report is None:
            print(f"{Colors.RED}No report created!{Colors.END}")
            time.sleep(2)
            return
        
        self.report_manager.display_report(self.current_report)
        input(f"\n{Colors.YELLOW}Press Enter...{Colors.END}")
    
    def load_save_report(self):
        """Load or save report"""
        print(f"\n{Colors.CYAN}Load/Save Report{Colors.END}")
        print("=" * 70)
        print(f"{Colors.YELLOW}1. Load from JSON")
        print(f"2. Save to JSON{Colors.END}")
        
        choice = input(f"\n{Colors.GREEN}Select: {Colors.END}").strip()
        
        if choice == '1':
            filename = input(f"{Colors.GREEN}JSON file path: {Colors.END}").strip()
            if os.path.exists(filename):
                try:
                    with open(filename, 'r') as f:
                        self.current_report = json.load(f)
                    print(f"{Colors.GREEN}✓ Report loaded!{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.END}")
            else:
                print(f"{Colors.RED}File not found!{Colors.END}")
        
        elif choice == '2':
            if self.current_report is None:
                print(f"{Colors.RED}No report to save!{Colors.END}")
            else:
                filename = input(f"{Colors.GREEN}Filename: {Colors.END}").strip()
                try:
                    with open(filename, 'w') as f:
                        json.dump(self.current_report, f, indent=2)
                    print(f"{Colors.GREEN}✓ Saved to {filename}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}Error: {e}{Colors.END}")
        
        time.sleep(2)
    
    def view_system_info(self):
        """View system information"""
        if self.medcrypt is None:
            print(f"{Colors.RED}Initialize system first!{Colors.END}")
            time.sleep(2)
            return
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}System Information{Colors.END}")
        print("=" * 70)
        
        print(f"\n{Colors.YELLOW}Encryption Configuration:{Colors.END}")
        print(f"  AES Key Size: 256 bits")
        print(f"  RSA Key Size: 2048 bits")
        print(f"  KDF: PBKDF2 (100,000 iterations)")
        
        print(f"\n{Colors.YELLOW}Security Features:{Colors.END}")
        print(f"  ✓ AES-256-CBC Encryption")
        print(f"  ✓ RSA-2048 Digital Signatures")
        print(f"  ✓ Diffie-Hellman Key Exchange")
        print(f"  ✓ LSB Steganography")
        print(f"  ✓ PBKDF2 Key Derivation")
        
        print(f"\n{Colors.YELLOW}Analytics Features:{Colors.END}")
        print(f"  ✓ Disease Pattern Analysis")
        print(f"  ✓ Security Threat Detection")
        print(f"  ✓ Performance Monitoring")
        print(f"  ✓ ML-Based Predictions")
        print(f"  ✓ Data Visualization")
        print(f"  ✓ CSV Export")
        
        print(f"\n{Colors.YELLOW}Database Statistics:{Colors.END}")
        print(f"  Reports: {len(self.analytics.data['reports'])}")
        print(f"  Operations: {len(self.analytics.data['operations'])}")
        print(f"  Security Events: {len(self.analytics.data['security_events'])}")
        print(f"  Performance Metrics: {len(self.analytics.data['performance_metrics'])}")
        
        time.sleep(4)
    
    def run(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            choice = input(f"\n{Colors.BOLD}{Colors.GREEN}Enter choice (0-20): {Colors.END}").strip()
            
            if choice == '1':
                self.initialize_system()
            elif choice == '2':
                self.create_report()
            elif choice == '3':
                self.encrypt_report()
            elif choice == '4':
                self.hide_in_image()
            elif choice == '5':
                self.extract_decrypt()
            elif choice == '6':
                self.complete_workflow()
            elif choice == '7':
                self.disease_analysis()
            elif choice == '8':
                self.security_analysis()
            elif choice == '9':
                self.performance_analysis()
            elif choice == '10':
                self.generate_report()
            elif choice == '11':
                self.visualize_data()
            elif choice == '12':
                self.export_csv()
            elif choice == '13':
                self.predict_disease()
            elif choice == '14':
                self.predict_breach()
            elif choice == '15':
                self.predict_load()
            elif choice == '16':
                self.encryption_efficiency()
            elif choice == '17':
                self.analyze_image()
            elif choice == '18':
                self.view_report()
            elif choice == '19':
                self.load_save_report()
            elif choice == '20':
                self.view_system_info()
            elif choice == '0':
                print(f"\n{Colors.CYAN}Thank you for using MEDCRYPT Analytics!{Colors.END}")
                print(f"{Colors.YELLOW}Stay secure! 🔒📊{Colors.END}\n")
                break
            else:
                print(f"{Colors.RED}Invalid choice!{Colors.END}")
                time.sleep(1)


# Main execution
if __name__ == "__main__":
    print(f"""
{Colors.BOLD}{Colors.CYAN}
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║                  MEDCRYPT v2.0 - ANALYTICS EDITION                ║
║                                                                    ║
║          Cybersecurity + Data Analytics + Machine Learning         ║
║                                                                    ║
║  This system combines advanced encryption with comprehensive       ║
║  data analytics to protect medical records and provide insights.   ║
║                                                                    ║
║  Features:                                                         ║
║  • AES-256 & RSA-2048 Encryption                                  ║
║  • LSB Steganography for invisible data hiding                    ║
║  • Disease pattern analysis & predictions                          ║
║  • Security threat monitoring & breach risk prediction             ║
║  • Performance analytics & system optimization                     ║
║  • Data visualization & CSV export                                ║
║  • Machine Learning predictions                                   ║
║                                                                    ║
║  Required packages:                                               ║
║  pip install opencv-python numpy pandas matplotlib cryptography    ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
{Colors.END}
    """)
    
    proceed = input(f"{Colors.GREEN}Press Enter to start MEDCRYPT...{Colors.END}")
    
    try:
        cli = MedCryptCLI()
        cli.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Application interrupted by user.{Colors.END}")
        print(f"{Colors.CYAN}Goodbye!{Colors.END}\n")
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.END}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)