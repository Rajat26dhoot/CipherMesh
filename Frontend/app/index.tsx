// app/index.tsx
import { useEffect } from "react";
import { router } from "expo-router";
import { View, Text, StyleSheet, ActivityIndicator, Image } from "react-native";

import { SafeAreaView } from "react-native-safe-area-context";

export default function Index() {
  useEffect(() => {
    const timer = setTimeout(() => {
      router.replace("/(auth)/welcome");
    }, 1500);

    return () => clearTimeout(timer);
  }, []);

  return (
    <SafeAreaView  style={styles.container}>
      <View style={styles.content}>
        {/* App Logo using Image */}
        <View style={styles.logoContainer}>
          <Image 
            source={require("../assets/images/logo.png")} // Adjust path if needed
            style={styles.logoImage}
            resizeMode="contain"
          />
        </View>

        {/* App Name */}
        <Text style={styles.appName}>
  <Text style={styles.cipher}>Cipher</Text>
  <Text style={styles.mesh}>Mesh</Text>
</Text>


        {/* Loading Indicator */}
        <ActivityIndicator 
          size="large" 
          color="#00D4AA" 
          style={styles.loader}
        />

        {/* Decorative Elements */}
        <View style={styles.decorativeElements}>
          <View style={[styles.dot, styles.dot1]} />
          <View style={[styles.dot, styles.dot2]} />
          <View style={[styles.dot, styles.dot3]} />
        </View>
      </View>
    </SafeAreaView >
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
  },
  content: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  logoContainer: {
    marginBottom: 30,
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoImage: {
    width: 120,
    height: 120,
  },
  appName: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#00D4AA', // changed to green-blue
    marginBottom: 40,
    letterSpacing: 1,
  },
  loader: {
    marginTop: 20,
  },
  decorativeElements: {
    position: 'absolute',
    width: '100%',
    height: '100%',
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    position: 'absolute',
  },
  dot1: {
    backgroundColor: '#00D4AA',
    top: '25%',
    left: '20%',
  },
  dot2: {
    backgroundColor: '#FF6B6B',
    top: '35%',
    right: '25%',
  },
  dot3: {
    backgroundColor: '#FFD700',
    bottom: '30%',
    left: '30%',
  },
});
