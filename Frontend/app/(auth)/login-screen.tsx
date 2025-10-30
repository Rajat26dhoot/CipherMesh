// app/(auth)/login-screen.tsx
import React, { useState } from 'react';
import { router } from 'expo-router';
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  Modal,
  ScrollView,
  ActivityIndicator,
} from 'react-native'; 
import { SafeAreaView } from "react-native-safe-area-context";
import * as SecureStore from "expo-secure-store";
import config from '../../config'
import { ArrowLeft } from 'lucide-react-native';

const LoginScreen = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const [showForgotModal, setShowForgotModal] = useState(false);
  const [fpIdentifier, setFpIdentifier] = useState(''); // email or username
  const [fpOldPassword, setFpOldPassword] = useState('');
  const [fpNewPassword, setFpNewPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);



  const handleLogin = async () => {
    try {
      const response = await fetch(`${config.BASE_URL}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });
  
      const data = await response.json();
  
      if (!response.ok || data.success === false) {
        throw new Error(data?.error?.message || "Login failed");
      }
  
      console.log("Login success:", data);
  
      // ✅ Store token securely
      const token = data?.data?.token;
      if (token) {
        await SecureStore.setItemAsync("authToken", token);
        console.log("Token saved:", token);
      }
  
      // ✅ Optionally save user info too
      const user = data?.data?.user;
      if (user) {
        await SecureStore.setItemAsync("userInfo", JSON.stringify(user));
        await SecureStore.setItemAsync("userId", user.id);
      }
  
      // Navigate after successful login
      router.replace("/(tabs)/home");
    } catch (error: any) {
      console.error("Login error:", error.message);
      alert(error.message);
    }
  };
  
  const handleSignUp = () => {
    console.log('Sign up pressed');
    router.push('/(auth)/signup-screen');
  };

  const handleForgotSubmit = async () => {
    if (!fpIdentifier || !fpOldPassword || !fpNewPassword) {
      alert("Please fill in all fields");
      return;
    }

    setIsLoading(true);
    try {
      const body = fpIdentifier.includes("@")
        ? { email: fpIdentifier, oldPassword: fpOldPassword, newPassword: fpNewPassword }
        : { username: fpIdentifier, oldPassword: fpOldPassword, newPassword: fpNewPassword };

      const res = await fetch(`${config.BASE_URL}/api/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || "Password reset failed");

      alert("Password reset successfully!");
      setShowForgotModal(false);
      setFpIdentifier('');
      setFpOldPassword('');
      setFpNewPassword('');
    } catch (err: any) {
      alert(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleBackToWelcome = () => {
    router.back();
  };

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.keyboardView}
      >
        <ScrollView contentContainerStyle={styles.scrollContainer}>
          {/* Header */}
          <View style={styles.header}>
            <TouchableOpacity style={styles.backButton} onPress={handleBackToWelcome}>
                <ArrowLeft size={28} color="#fff" strokeWidth={2.5} />
            </TouchableOpacity>
            <Text style={styles.title}>Welcome Back</Text>
            <Text style={styles.subtitle}>Sign in to continue</Text>
          </View>

          {/* Login Form */}
          <View style={styles.formContainer}>
            {/* Email Input */}
            <View style={styles.inputContainer}>
              <Text style={styles.label}>Email</Text>
              <TextInput
                style={styles.input}
                value={email}
                onChangeText={setEmail}
                placeholder="Enter your email"
                placeholderTextColor="#666666"
                keyboardType="email-address"
                autoCapitalize="none"
                autoCorrect={false}
              />
            </View>

            {/* Password Input */}
            <View style={styles.inputContainer}>
              <Text style={styles.label}>Password</Text>
              <View style={styles.passwordContainer}>
                <TextInput
                  style={styles.passwordInput}
                  value={password}
                  onChangeText={setPassword}
                  placeholder="Enter your password"
                  placeholderTextColor="#666666"
                  secureTextEntry={!showPassword}
                  autoCapitalize="none"
                  autoCorrect={false}
                />
                <TouchableOpacity
                  style={styles.eyeButton}
                  onPress={() => setShowPassword(!showPassword)}
                >
                  <Text style={styles.eyeText}>{showPassword ? '👁️' : '👁️‍🗨️'}</Text>
                </TouchableOpacity>
              </View>
            </View>

            {/* Forgot Password */}
            <TouchableOpacity onPress={() => setShowForgotModal(true)}>
              <Text style={styles.forgotPassword}>Forgot Password?</Text>
            </TouchableOpacity>

            {/* Login Button */}
            <TouchableOpacity style={styles.loginButton} onPress={handleLogin}>
              <Text style={styles.loginButtonText}>Sign In</Text>
            </TouchableOpacity>

           

            <View style={styles.signUpContainer}>
            <Text style={styles.signUpText}>Don't have an account? </Text>
            <TouchableOpacity onPress={handleSignUp}>
              <Text style={styles.signUpLink}>Sign Up</Text>
            </TouchableOpacity>
          </View>

           
          </View>
        

          {/* Decorative Elements */}
          <View style={styles.decorativeElements}>
            <View style={[styles.coin, styles.coin1]}>
              <Text style={styles.coinText}>₿</Text>
            </View>
            <View style={[styles.diamond, styles.diamond1]} />
            <View style={[styles.dot, styles.dot1]} />
            <View style={[styles.dot, styles.dot2]} />
          </View>
        </ScrollView>
      </KeyboardAvoidingView>

      <Modal
        visible={showForgotModal}
        animationType="slide"
        transparent
        onRequestClose={() => setShowForgotModal(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContainer}>
            <Text style={styles.modalTitle}>Reset Password</Text>

            <TextInput
              style={styles.modalInput}
              placeholder="Username or Email"
              placeholderTextColor="#888"
              value={fpIdentifier}
              onChangeText={setFpIdentifier}
            />
             {/* Old Password */}
          <View style={styles.passwordContainer2}>
            <TextInput
              style={styles.passwordInput2}
              placeholder="Enter old password"
              placeholderTextColor="#666"
              secureTextEntry={!showOldPassword}
              value={fpOldPassword}
              onChangeText={setFpOldPassword}
            />
            <TouchableOpacity
              style={styles.eyeButton2}
              onPress={() => setShowOldPassword(!showOldPassword)}
            >
              <Text style={styles.eyeText2}>
                {showOldPassword ? "👁️" : "👁️‍🗨️"}
              </Text>
            </TouchableOpacity>
          </View>

          {/* New Password */}
          <View style={styles.passwordContainer2}>
            <TextInput
              style={styles.passwordInput2}
              placeholder="Enter new password"
              placeholderTextColor="#666"
              secureTextEntry={!showNewPassword}
              value={fpNewPassword}
              onChangeText={setFpNewPassword}
            />
            <TouchableOpacity
              style={styles.eyeButton2}
              onPress={() => setShowNewPassword(!showNewPassword)}
            >
              <Text style={styles.eyeText2}>
                {showNewPassword ? "👁️" : "👁️‍🗨️"}
              </Text>
            </TouchableOpacity>
          </View>


            {isLoading ? (
              <ActivityIndicator color="#00D4AA" style={{ marginVertical: 10 }} />
            ) : (
              <TouchableOpacity style={styles.modalButton} onPress={handleForgotSubmit}>
                <Text style={styles.modalButtonText}>Update Password</Text>
              </TouchableOpacity>
            )}

            <TouchableOpacity onPress={() => setShowForgotModal(false)}>
              <Text style={styles.modalCancel}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>

    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
  },
  keyboardView: {
    flex: 1,
  },
  scrollContainer: {
    flexGrow: 1,
    paddingHorizontal: 24,
    paddingVertical: 40,
  },
  header: {
    alignItems: 'center',
    marginBottom: 40,
    position: 'relative',
  },
  backButton: {
    position: 'absolute',
    left: 0,
    top: 0,
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#2a2a2a',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1,
  },
  backButtonText: {
    fontSize: 24,
    color: '#ffffff',
    fontWeight: 'bold',
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#888888',
  },
  formContainer: {
    flex: 1,
  },
  inputContainer: {
    marginBottom: 20,
  },
  label: {
    fontSize: 16,
    color: '#ffffff',
    marginBottom: 8,
    fontWeight: '500',
  },
  input: {
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 16,
    fontSize: 16,
    color: '#ffffff',
    borderWidth: 1,
    borderColor: '#3a3a3a',
  },
  passwordContainer: {
    position: 'relative',
  },
  passwordInput: {
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 16,
    fontSize: 16,
    color: '#ffffff',
    borderWidth: 1,
    borderColor: '#3a3a3a',
    paddingRight: 50,
  },
  eyeButton: {
    position: 'absolute',
    right: 16,
    top: 16,
  },
  eyeText: {
    fontSize: 18,
  },
  forgotPassword: {
    color: '#00D4AA',
    fontSize: 14,
    textAlign: 'right',
    marginBottom: 30,
  },
  loginButton: {
    backgroundColor: '#00D4AA',
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: 'center',
    marginBottom: 30,
    shadowColor: '#00D4AA',
    shadowOffset: {
      width: 0,
      height: 4,
    },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  loginButtonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  dividerContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 30,
  },
  divider: {
    flex: 1,
    height: 1,
    backgroundColor: '#3a3a3a',
  },
  dividerText: {
    color: '#888888',
    marginHorizontal: 16,
    fontSize: 14,
  },
  socialButton: {
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#3a3a3a',
  },
  appleButton: {
    backgroundColor: '#000000',
  },
  socialButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '500',
  },
  signUpContainer: {
    marginTop:20,
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
  },
  signUpText: {
    color: '#888888',
    fontSize: 16,
  },
  signUpLink: {
    color: '#00D4AA',
    fontSize: 16,
    fontWeight: 'bold',
  },
  decorativeElements: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    pointerEvents: 'none',
  },
  coin: {
    width: 30,
    height: 30,
    borderRadius: 15,
    backgroundColor: '#FFD700',
    alignItems: 'center',
    justifyContent: 'center',
    position: 'absolute',
  },
  coin1: {
    top: 100,
    right: 30,
  },
  coinText: {
    color: '#1a1a1a',
    fontSize: 14,
    fontWeight: 'bold',
  },
  diamond: {
    width: 8,
    height: 8,
    transform: [{ rotate: '45deg' }],
    position: 'absolute',
  },
  diamond1: {
    backgroundColor: '#FF6B6B',
    bottom: 60,
    left: 30,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    position: 'absolute',
  },
  dot1: {
    backgroundColor: '#00D4AA',
    top: 120,
    left: 50,
  },
  dot2: {
    backgroundColor: '#FFD700',
    bottom: 50,
    right: 50,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.6)",
    justifyContent: "center",
    alignItems: "center",
  },
  modalContainer: {
    width: "85%",
    backgroundColor: "#1a1a1a",
    borderRadius: 16,
    padding: 24,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 10,
  },
  modalTitle: {
    color: "#ffffff",
    fontSize: 22,
    fontWeight: "bold",
    marginBottom: 20,
    textAlign: "center",
  },
  modalInput: {
    backgroundColor: "#2a2a2a",
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 14,
    fontSize: 16,
    color: "#ffffff",
    borderWidth: 1,
    borderColor: "#3a3a3a",
    marginBottom: 16,
  },
  passwordContainer2: {
    position: "relative",
    marginBottom: 16,
  },
  passwordInput2: {
    backgroundColor: "#2a2a2a",
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 14,
    fontSize: 16,
    color: "#ffffff",
    borderWidth: 1,
    borderColor: "#3a3a3a",
    paddingRight: 50,
  },
  eyeButton2: {
    position: "absolute",
    right: 12,
    top: 12,
  },
  eyeText2: {
    fontSize: 18,
    color: "#ccc",
  },
  modalButton: {
    backgroundColor: "#00D4AA",
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
    marginTop: 10,
    shadowColor: "#00D4AA",
    shadowOffset: { width: 0, height: 3 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 5,
  },
  modalButtonText: {
    color: "#ffffff",
    fontSize: 17,
    fontWeight: "bold",
  },
  modalCancel: {
    color: "#888888",
    fontSize: 15,
    textAlign: "center",
    marginTop: 16,
  },
});

export default LoginScreen;