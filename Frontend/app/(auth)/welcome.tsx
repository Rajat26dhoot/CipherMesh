// app/(auth)/welcome.tsx
import React from 'react';
import { router } from 'expo-router';
import {
  View,
  Text,
  StyleSheet,
  Image,
  TouchableOpacity,
  Dimensions,
} from 'react-native';
import { SafeAreaView } from "react-native-safe-area-context";

const { width, height } = Dimensions.get('window');

const Welcome = () => {
  const handleGetStarted = () => {
    // Navigate to login screen
    router.push('/(auth)/login-screen');
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        {/* Decorative Elements */}
        <View style={styles.decorativeElements}>
          {/* Top left coin */}
          <View style={[styles.coin, styles.topLeftCoin]}>
            <Text style={styles.coinText}>$</Text>
          </View>
          
          {/* Lightning bolts and shapes */}
          <View style={[styles.lightning, styles.lightning1]} />
          <View style={[styles.lightning, styles.lightning2]} />
          <View style={[styles.diamond, styles.diamond1]} />
          <View style={[styles.diamond, styles.diamond2]} />
          <View style={[styles.dot, styles.dot1]} />
          <View style={[styles.dot, styles.dot2]} />
          <View style={[styles.dot, styles.dot3]} />
        </View>

        {/* Main Illustration */}
        <View style={styles.illustrationContainer}>
          <Image
            source={require('../../assets/images/welcome.png')}
            style={styles.mainIllustration}
            resizeMode="contain"
          />
        </View>

        {/* Main Content */}
        <View style={styles.textContainer}>
        <Text style={styles.title}>Share & Access{'\n'}Files Seamlessly</Text>
        <Text style={styles.subtitle}>
            Decentralized. Secure. Instant.{'\n'}Your files, your control.
        </Text>
        </View>


        {/* Get Started Button */}
        <TouchableOpacity style={styles.getStartedButton} onPress={handleGetStarted}>
          <Text style={styles.buttonText}>Get Started</Text>
        </TouchableOpacity>

        {/* Next Button */}
        
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
  },
  content: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 40,
  },
  decorativeElements: {
    position: 'absolute',
    width: width,
    height: height,
    top: 0,
    left: 0,
  },
  coin: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#FFD700',
    alignItems: 'center',
    justifyContent: 'center',
    position: 'absolute',
  },
  topLeftCoin: {
    top: 100,
    left: 30,
  },
  coinText: {
    color: '#1a1a1a',
    fontSize: 18,
    fontWeight: 'bold',
  },
  lightning: {
    width: 0,
    height: 0,
    position: 'absolute',
    borderLeftWidth: 8,
    borderRightWidth: 8,
    borderTopWidth: 15,
    borderLeftColor: 'transparent',
    borderRightColor: 'transparent',
  },
  lightning1: {
    borderTopColor: '#FFD700',
    top: 120,
    right: 50,
    transform: [{ rotate: '15deg' }],
  },
  lightning2: {
    borderTopColor: '#00D4AA',
    bottom: 200,
    left: 40,
    transform: [{ rotate: '-30deg' }],
  },
  diamond: {
    width: 12,
    height: 12,
    transform: [{ rotate: '45deg' }],
    position: 'absolute',
  },
  diamond1: {
    backgroundColor: '#00D4AA',
    top: 200,
    right: 80,
  },
  diamond2: {
    backgroundColor: '#FF6B6B',
    bottom: 250,
    right: 60,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    position: 'absolute',
  },
  dot1: {
    backgroundColor: '#00D4AA',
    top: 180,
    left: 80,
  },
  dot2: {
    backgroundColor: '#FFD700',
    bottom: 180,
    right: 30,
  },
  dot3: {
    backgroundColor: '#FF6B6B',
    top: 250,
    right: 40,
  },
  illustrationContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 60,
    marginBottom: 20,
  },
  mainIllustration: {
    width: width * 0.7,
    height: height * 0.4,
  },
  textContainer: {
    alignItems: 'center',
    marginBottom: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ffffff',
    textAlign: 'center',
    marginBottom: 16,
    lineHeight: 36,
  },
  subtitle: {
    fontSize: 16,
    color: '#888888',
    textAlign: 'center',
    lineHeight: 24,
  },
  getStartedButton: {
    backgroundColor: '#00D4AA',
    paddingHorizontal: 40,
    paddingVertical: 16,
    borderRadius: 25,
    marginBottom: 20,
    shadowColor: '#00D4AA',
    shadowOffset: {
      width: 0,
      height: 4,
    },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  buttonText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: 'bold',
    textAlign: 'center',
  },
});

export default Welcome;