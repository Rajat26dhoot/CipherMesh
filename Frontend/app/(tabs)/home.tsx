// app/(tabs)/home.tsx
import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Image,
  ScrollView,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { router } from 'expo-router';
import { SafeAreaView } from "react-native-safe-area-context";
import * as SecureStore from 'expo-secure-store';
import config from '../../config'; 

interface UserData {
  username: string;
  firstName: string;
  lastName: string;
  email: string;
  blockchainAddress?: string;
  publicKey?: string;
}

const HomeScreen = () => {
  const [userData, setUserData] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const handleNotifications = () => {
    console.log('Notifications pressed');
  };

  const handleProfile = () => {
    router.push('/(tabs)/profile');
  };

  const handleSend = () => {
    router.push('/(tabs)/send');
  };

  const handleReceive = () => {
    router.push('/(tabs)/receive');
  };

  const fetchUserData = async () => {
    try {
      setLoading(true);
      setError(null);
  
      const token = await SecureStore.getItemAsync("authToken");
      if (!token) {
        setError("No authentication token found");
        router.replace("/(auth)/welcome");
        return;
      }
  
      const response = await fetch(`${config.BASE_URL}/api/me`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
  
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          await SecureStore.deleteItemAsync("authToken");
          router.replace("/(auth)/welcome");
          return;
        }
        throw new Error(`HTTP error! status: ${response.status}`);
      }
  
      const data = await response.json();
  
      if (!data.success) {
        throw new Error(data.error || "Failed to load user data");
      }
  
      setUserData(data.data);
    } catch (err) {
      console.error("Error fetching user data:", err);
      setError(err instanceof Error ? err.message : "Failed to fetch user data");
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchUserData();
  }, []);

  const getFirstLetter = (firstName: string): string => {
    return firstName ? firstName.charAt(0).toUpperCase() : '?';
  };

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.appName}>CipherMesh</Text>
        <View style={styles.headerRight}>
          <TouchableOpacity style={styles.iconButton} onPress={handleNotifications}>
            <Ionicons name="notifications-outline" size={24} color="#ffffff" />
          </TouchableOpacity>
          <TouchableOpacity style={styles.profileButton} onPress={handleProfile}>
            <View style={styles.profileImage}>
              <Text style={styles.profileInitial}>
              {getFirstLetter(userData?.username || '')}
              </Text>
            </View>
          </TouchableOpacity>
        </View>
      </View>

      <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
        {/* Main Illustration */}
        <View style={styles.illustrationContainer}>
          <Image
            source={require('../../assets/images/welcome.png')}
            style={styles.mainIllustration}
            resizeMode="contain"
          />
        </View>

        {/* Share Offline Section */}
        <View style={styles.shareSection}>
          <Text style={styles.shareTitle}>Share Files</Text>
          <Text style={styles.shareSubtitle}>
               Send encrypted files safely to nearby friends{'\n'} fast, private 
          </Text>

          {/* Action Buttons */}
          <View style={styles.actionButtons}>
            <TouchableOpacity style={[styles.actionButton, styles.sendButton]} onPress={handleSend}>
              <View style={styles.buttonIcon}>
                <Ionicons name="arrow-up" size={24} color="#ffffff" />
              </View>
              <Text style={styles.buttonText}>Send</Text>
            </TouchableOpacity>

            <TouchableOpacity style={[styles.actionButton, styles.receiveButton]} onPress={handleReceive}>
              <View style={styles.buttonIcon}>
                <Ionicons name="arrow-down" size={24} color="#ffffff" />
              </View>
              <Text style={styles.buttonText}>Receive</Text>
            </TouchableOpacity>
          </View>
        </View>

        
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2a2a',
  },
  appName: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  iconButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#2a2a2a',
    alignItems: 'center',
    justifyContent: 'center',
  },
  profileButton: {
    width: 40,
    height: 40,
  },
  profileImage: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#00D4AA',
    alignItems: 'center',
    justifyContent: 'center',
  },
  profileInitial: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  content: {
    flex: 1,
    paddingHorizontal: 20,
  },
  illustrationContainer: {
    alignItems: 'center',
    marginVertical: 40,
  },
  mainIllustration: {
    width: 250,
    height: 200,
  },
  shareSection: {
    alignItems: 'center',
    marginBottom: 40,
  },
  shareTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 12,
  },
  shareSubtitle: {
    fontSize: 16,
    color: '#888888',
    textAlign: 'center',
    lineHeight: 24,
    marginBottom: 40,
  },
  actionButtons: {
    flexDirection: 'row',
    gap: 40,
  },
  actionButton: {
    alignItems: 'center',
    gap: 8,
  },
  buttonIcon: {
    width: 60,
    height: 60,
    borderRadius: 30,
    borderWidth:2,
    borderColor:'white',
    alignItems: 'center',
    justifyContent: 'center',
    shadowOffset: {
      width: 0,
      height: 4,
    },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  sendButton: {},
  receiveButton: {},
  sendButton: {
    shadowColor: '#4A90E2',
  },
  receiveButton: {
    shadowColor: '#00D4AA',
  },
  buttonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '600',
  },
  recentSection: {
    marginBottom: 30,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 20,
  },
  activityItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 16,
    paddingHorizontal: 16,
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    marginBottom: 12,
  },
  activityIcon: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: '#3a3a3a',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  activityContent: {
    flex: 1,
  },
  activityTitle: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '500',
    marginBottom: 4,
  },
  activityTime: {
    color: '#888888',
    fontSize: 14,
  },
  activityAmount: {
    color: '#00D4AA',
    fontSize: 14,
    fontWeight: '600',
  },
});

export default HomeScreen;