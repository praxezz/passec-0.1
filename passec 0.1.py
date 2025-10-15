import re
import math
import hashlib
from typing import Optional, Tuple

class SimplePasswordChecker:
    """Fast, offline password checking - no dependencies needed"""
    
    @staticmethod
    def quick_check(password: str) -> dict:
        """Quick password strength check - instant results"""
        score = 0
        feedback = []
        
        # Length check
        length = len(password)
        if length >= 12:
            score += 2
            feedback.append("✓ Good length")
        elif length >= 8:
            score += 1
            feedback.append("✓ Acceptable length")
        else:
            feedback.append("✗ Too short")
        
        # Character types
        if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
            score += 1
            feedback.append("✓ Mixed case letters")
        else:
            feedback.append("✗ Missing uppercase or lowercase")
        
        if re.search(r'[0-9]', password):
            score += 1
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("✗ No numbers")
        
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 1
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ No special characters")
        
        # Pattern checks (penalties)
        if re.search(r'(.)\1{2,}', password):
            score -= 1
            feedback.append("⚠ Repeated characters")
        
        if re.search(r'(123|234|345|456|567|678|789|abc|bcd|cde)', password.lower()):
            score -= 1
            feedback.append("⚠ Sequential patterns")
        
        # Determine strength
        score = max(0, score)
        if score >= 4:
            strength = "Strong"
            color = "green"
        elif score == 3:
            strength = "Moderate"
            color = "yellow"
        elif score == 2:
            strength = "Weak"
            color = "orange"
        else:
            strength = "Very Weak"
            color = "red"
        
        return {
            'strength': strength,
            'score': score,
            'max_score': 5,
            'feedback': feedback,
            'color': color,
            'mode': 'quick'
        }


class AdvancedPasswordChecker:
    """Comprehensive password analysis with breach checking"""
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy in bits"""
        charset = 0
        if re.search(r'[a-z]', password): charset += 26
        if re.search(r'[A-Z]', password): charset += 26
        if re.search(r'[0-9]', password): charset += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset += 32
        
        if charset == 0:
            return 0.0
        
        entropy = len(password) * math.log2(charset)
        return round(entropy, 2)
    
    @staticmethod
    def estimate_crack_time(entropy: float) -> str:
        """Estimate time to crack password"""
        guesses_per_second = 1_000_000_000
        total_combinations = 2 ** entropy
        seconds = total_combinations / guesses_per_second
        
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 2592000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000:
            return f"{int(seconds / 2592000)} months"
        else:
            years = int(seconds / 31536000)
            if years > 1_000_000:
                return "Centuries (virtually uncrackable)"
            return f"{years:,} years"
    
    @staticmethod
    def check_breach(password: str) -> Tuple[bool, int]:
        """Check if password exists in breach database (requires internet)"""
        try:
            import requests
            
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=3)
            
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
            
            return False, 0
        except ImportError:
            print("⚠ 'requests' library not installed. Skipping breach check.")
            return False, 0
        except Exception:
            print("⚠ Breach check failed (internet issue). Continuing...")
            return False, 0
    
    @staticmethod
    def deep_analysis(password: str) -> dict:
        """Comprehensive password analysis"""
        score = 0
        feedback = []
        
        # Length analysis
        length = len(password)
        if length >= 16:
            score += 30
            feedback.append("✓ Excellent length (16+ characters)")
        elif length >= 12:
            score += 20
            feedback.append("✓ Good length (12+ characters)")
        elif length >= 8:
            score += 10
            feedback.append("✓ Acceptable length (8+ characters)")
        else:
            score += 5
            feedback.append("✗ Too short (minimum 8 characters)")
        
        # Character diversity
        char_types = 0
        if re.search(r'[a-z]', password): char_types += 1
        if re.search(r'[A-Z]', password): char_types += 1
        if re.search(r'[0-9]', password): char_types += 1
        if re.search(r'[^a-zA-Z0-9]', password): char_types += 1
        
        if char_types == 4:
            score += 25
            feedback.append("✓ Excellent character diversity")
        elif char_types == 3:
            score += 15
            feedback.append("✓ Good character diversity")
        elif char_types == 2:
            score += 8
            feedback.append("⚠ Limited character diversity")
        else:
            score += 3
            feedback.append("✗ Poor character diversity")
        
        # Calculate entropy
        entropy = AdvancedPasswordChecker.calculate_entropy(password)
        
        if entropy >= 80:
            score += 25
            feedback.append(f"✓ Very high entropy ({entropy} bits)")
        elif entropy >= 60:
            score += 20
            feedback.append(f"✓ High entropy ({entropy} bits)")
        elif entropy >= 40:
            score += 10
            feedback.append(f"⚠ Moderate entropy ({entropy} bits)")
        else:
            score += 5
            feedback.append(f"✗ Low entropy ({entropy} bits)")
        
        # Pattern checks
        issues = 0
        if re.search(r'(.)\1{2,}', password):
            issues += 1
            feedback.append("⚠ Contains repeated characters")
        
        if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|qwer|asdf)', password.lower()):
            issues += 1
            feedback.append("⚠ Contains sequential patterns")
        
        if re.search(r'password|admin|welcome|login|123456', password.lower()):
            issues += 1
            feedback.append("⚠ Contains common words")
        
        score -= issues * 5
        
        # Uniqueness check
        unique_ratio = len(set(password)) / length if length > 0 else 0
        if unique_ratio >= 0.8:
            score += 10
            feedback.append("✓ High character uniqueness")
        elif unique_ratio < 0.5:
            score -= 5
            feedback.append("⚠ Many repeated characters")
        
        # Cap score
        score = max(0, min(100, score))
        
        # Check breaches
        is_breached, breach_count = AdvancedPasswordChecker.check_breach(password)
        
        if is_breached:
            score = min(score, 15)  # Cap at 15 if breached
            feedback.insert(0, f"🚨 CRITICAL: Found in {breach_count:,} data breaches!")
        
        # Determine strength
        if score >= 85:
            strength = "Very Strong"
            color = "green"
        elif score >= 70:
            strength = "Strong"
            color = "blue"
        elif score >= 50:
            strength = "Moderate"
            color = "yellow"
        elif score >= 30:
            strength = "Weak"
            color = "orange"
        else:
            strength = "Very Weak"
            color = "red"
        
        crack_time = AdvancedPasswordChecker.estimate_crack_time(entropy)
        
        return {
            'strength': strength,
            'score': score,
            'max_score': 100,
            'feedback': feedback,
            'color': color,
            'entropy': entropy,
            'crack_time': crack_time,
            'is_breached': is_breached,
            'breach_count': breach_count,
            'mode': 'deep'
        }


def display_results(result: dict, password_length: int):
    """Display results in a user-friendly format"""
    colors = {
        'red': '\033[91m',
        'orange': '\033[93m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'green': '\033[92m',
        'green': '\033[96m',
        'bold': '\033[1m',
        'reset': '\033[0m'
    }
    
    c = colors
    color = colors.get(result['color'], colors['reset'])
    
    # Header
    mode_name = "Quick Check" if result['mode'] == 'quick' else "Deep Analysis"
    print(f"\n{c['green']}{'=' * 60}{c['reset']}")
    print(f"{c['bold']}{c['green']}       PASSWORD STRENGTH: {mode_name.upper()}{c['reset']}")
    print(f"{c['green']}{'=' * 60}{c['reset']}\n")
    
    # Main results
    print(f"{c['bold']}Strength:{c['reset']} {color}{result['strength']}{c['reset']}")
    print(f"{c['bold']}Score:{c['reset']} {color}{result['score']}/{result['max_score']}{c['reset']}")
    
    # Progress bar
    bar_width = 40
    filled = int((result['score'] / result['max_score']) * bar_width)
    bar = '█' * filled + '░' * (bar_width - filled)
    print(f"{c['bold']}Visual:{c['reset']} {color}{bar}{c['reset']}")
    
    # Extra metrics for deep analysis
    if result['mode'] == 'deep':
        print(f"\n{c['bold']}{c['green']}Technical Details:{c['reset']}")
        print(f"  • Password Length: {password_length} characters")
        print(f"  • Entropy: {result['entropy']} bits")
        print(f"  • Estimated Crack Time: {c['yellow']}{result['crack_time']}{c['reset']}")
        
        if result['is_breached']:
            print(f"\n{c['bold']}{c['red']}⚠️  SECURITY ALERT:{c['reset']}")
            print(f"  Found in {c['red']}{result['breach_count']:,}{c['reset']} known breaches!")
            print(f"  {c['red']}Change this password immediately!{c['reset']}")
        else:
            print(f"\n{c['green']}✓ Not found in known data breaches{c['reset']}")
    
    # Feedback
    print(f"\n{c['bold']}{c['green']}Analysis:{c['reset']}")
    print("-" * 60)
    for item in result['feedback']:
        if '✓' in item:
            print(f"  {c['green']}{item}{c['reset']}")
        elif '✗' in item:
            print(f"  {colors['red']}{item}{c['reset']}")
        elif '⚠' in item or '🚨' in item:
            print(f"  {colors['yellow']}{item}{c['reset']}")
        else:
            print(f"  {item}")
    
    # Recommendations for weak passwords
    if result['score'] < 60:
        print(f"\n{c['bold']}{c['green']}💡 Tips to Improve:{c['reset']}")
        print("  • Use at least 12 characters (longer is better)")
        print("  • Mix uppercase, lowercase, numbers, and symbols")
        print("  • Avoid personal info and common words")
        print("  • Consider using a passphrase (e.g., 'Blue$Sky-Coffee42')")
    
    print(f"\n{c['green']}{'=' * 60}{c['reset']}\n")


def main():
    """Main application"""
    c = {
        'green': '\033[92m',
        'yellow': '\033[93m',
        'bold': '\033[1m',
        'reset': '\033[0m'
    }
    
    print(f"\n{c['bold']}{c['green']}╔═════════════════════════════════════════════════════════════════════════╗{c['reset']}")
    print(f"{c['bold']}{c['green']}    ██████╗  █████╗ ███████╗███████╗███████╗ ██████╗     ██████╗    ██╗             {c['reset']}")
    print(f"{c['bold']}{c['green']}    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝    ██╔═████╗  ███║           {c['reset']}")
    print(f"{c['bold']}{c['green']}    ██████╔╝███████║███████╗███████╗█████╗  ██║         ██║██╔██║  ╚██║              {c['reset']}")
    print(f"{c['bold']}{c['green']}    ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║         ████╔╝██║   ██║               {c['reset']}")
    print(f"{c['bold']}{c['green']}    ██║     ██║  ██║███████║███████║███████╗╚██████╗    ╚██████╔╝██╗██║              {c['reset']}")
    print(f"{c['bold']}{c['green']}    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝     ╚═════╝ ╚═╝╚═╝               {c['reset']}")
    print(f"{c['bold']}{c['green']}╚═════════════════════════════════════════════════════════════════════════╝{c['reset']}\n")
    
    while True:
        # Mode selection
        print(f"{c['bold']}Choose analysis mode:{c['reset']}")
        print("  1. Quick Check (instant, works offline)")
        print("  2. Deep Analysis (comprehensive, requires internet)")
        print("  q. Quit")
        
        mode = input(f"\n{c['bold']}Select mode (1/2/q):{c['reset']} ").strip().lower()
        
        if mode in ['q', 'quit', 'exit']:
            print(f"\n{c['green']}Stay secure! 🛡️{c['reset']}\n")
            break
        
        if mode not in ['1', '2']:
            print(f"{c['yellow']}⚠ Please enter 1, 2, or q{c['reset']}\n")
            continue
        
        # Get password
        password = input(f"\n{c['bold']}Enter password to check:{c['reset']} ")
        
        if not password:
            print(f"{c['yellow']}⚠ Please enter a password!{c['reset']}\n")
            continue
        
        # Analyze based on mode
        if mode == '1':
            print(f"\n{c['yellow']}Analyzing (quick mode)...{c['reset']}")
            result = SimplePasswordChecker.quick_check(password)
        else:
            print(f"\n{c['yellow']}Analyzing (deep mode - checking breaches)...{c['reset']}")
            result = AdvancedPasswordChecker.deep_analysis(password)
        
        # Display results
        display_results(result, len(password))
        
        # Continue?
        again = input(f"{c['bold']}Check another password? (y/n):{c['reset']} ").lower()
        if again not in ['y', 'yes']:
            print(f"\n{c['green']}Stay secure! 🛡️{c['reset']}\n")
            break


if __name__ == "__main__":
    main()