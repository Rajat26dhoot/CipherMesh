import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
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

const ProfileScreen = () => {
  const [userData, setUserData] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchUserData();
  }, []);

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
      console.log("✅ User data fetched:", data);
  
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
  
  const getFirstLetter = (firstName: string): string => {
    return firstName ? firstName.charAt(0).toUpperCase() : '?';
  };

  const handleBack = () => router.back();

  const handleLogout = async () => {
    try {
      await SecureStore.deleteItemAsync("authToken");
      console.log("Token removed");
      router.replace('/(auth)/welcome');
    } catch (error) {
      console.error('Error during logout:', error);
      router.replace('/(auth)/welcome');
    }
  };

  const handleTermsOfService = () => {
    console.log('Terms of Service pressed');
  };

  const handleRefresh = () => fetchUserData();

  const handleRequestSent = () => {
    router.push('/(screen)/RequestSentScreen');
  };

  const handleRequestReceived = () => {
    router.push('/(screen)/RequestReceivedScreen');
  };

  return (
    <SafeAreaView style={styles.container}  edges={['top']}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={handleBack}>
          <Ionicons name="arrow-back" size={24} color="#ffffff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Profile</Text>
      </View>

      <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
        {/* Decorative Background */}
        <View style={styles.decorativeBackground}>
          <View style={[styles.decorativeCircle, styles.circle1]} />
          <View style={[styles.decorativeCircle, styles.circle2]} />
        </View>

        {/* Profile Info */}
        <View style={styles.profileInfo}>
          {loading ? (
            <View style={styles.loadingContainer}>
              <ActivityIndicator size="large" color="#00D4AA" />
              <Text style={styles.loadingText}>Loading profile...</Text>
            </View>
          ) : error ? (
            <View style={styles.errorContainer}>
              <Ionicons name="alert-circle" size={48} color="#FF6B6B" />
              <Text style={styles.errorText}>{error}</Text>
              <TouchableOpacity style={styles.retryButton} onPress={handleRefresh}>
                <Text style={styles.retryButtonText}>Retry</Text>
              </TouchableOpacity>
            </View>
          ) : (
            <>
              <View style={styles.profileImageContainer}>
                <View style={styles.profileInitial}>
                  <Text style={styles.initialText}>
                    {getFirstLetter(userData?.username || '')}
                  </Text>
                </View>
                
              </View>
              <Text style={styles.userName}>{userData?.username || 'Unknown User'}</Text>
            </>
          )}
        </View>

        {/* Account Info Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Account Info</Text>
          
          {/* Email */}
          <View style={styles.menuItem}>
            <View style={styles.menuItemLeft}>
              <View style={[styles.menuIcon, { backgroundColor: '#FF6B6B' }]}>
                <Ionicons name="mail" size={20} color="#ffffff" />
              </View>
              <Text style={styles.menuText}>Email</Text>
            </View>
            <Text style={styles.menuValue}>{userData?.email || 'Not available'}</Text>
          </View>

          {/* Blockchain Address */}
          <View style={styles.menuItem}>
            <View style={styles.menuItemLeft}>
              <View style={[styles.menuIcon, { backgroundColor: '#4A90E2' }]}>
                <Ionicons name="cube" size={20} color="#ffffff" />
              </View>
              <Text style={styles.menuText}>BC Address</Text>
            </View>
            <Text numberOfLines={1} ellipsizeMode="middle" style={styles.menuValueSmall}>
              {userData?.blockchainAddress || 'Not available'}
            </Text>
          </View>

          {/* Public Key */}
          <View style={styles.menuItem}>
            <View style={styles.menuItemLeft}>
              <View style={[styles.menuIcon, { backgroundColor: '#FFD700' }]}>
                <Ionicons name="key" size={20} color="#1a1a1a" />
              </View>
              <Text style={styles.menuText}>Public Key</Text>
            </View>
            <Text numberOfLines={1} ellipsizeMode="middle" style={styles.menuValueSmall}>
              {userData?.publicKey || 'Not available'}
            </Text>
          </View>

        </View>

        {/* Settings Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Settings</Text>
          
          {/* Request Sent */}
          <TouchableOpacity style={styles.menuItem} onPress={handleRequestSent}>
            <View style={styles.menuItemLeft}>
              <View style={[styles.menuIcon, { backgroundColor: '#2ECC71' }]}>
                <Ionicons name="send" size={20} color="#ffffff" />
              </View>
              <Text style={styles.menuText}>Request Sent</Text>
            </View>
            <Ionicons name="chevron-forward" size={20} color="#888888" />
          </TouchableOpacity>

          {/* Request Received */}
          <TouchableOpacity style={styles.menuItem} onPress={handleRequestReceived}>
            <View style={styles.menuItemLeft}>
              <View style={[styles.menuIcon, { backgroundColor: '#3498DB' }]}>
                <Ionicons name="download" size={20} color="#ffffff" />
              </View>
              <Text style={styles.menuText}>Request Received</Text>
            </View>
            <Ionicons name="chevron-forward" size={20} color="#888888" />
          </TouchableOpacity>
        </View>

        {/* Resources Section */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Resources</Text>
          
          <TouchableOpacity style={styles.menuItem}>
            <View style={styles.menuItemLeft}>
              <View style={[styles.menuIcon, { backgroundColor: '#E67E22' }]}>
                <Ionicons name="document-text" size={20} color="#ffffff" />
              </View>
              <Text style={styles.menuText}>Terms of Service</Text>
            </View>
          </TouchableOpacity>
        </View>

        {/* Logout Button */}
        <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
          <Ionicons name="log-out" size={20} color="#FF6B6B" />
          <Text style={styles.logoutText}>Logout</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#1a1a1a' },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2a2a',
  },
  backButton: {
    width: 40, height: 40, borderRadius: 20, backgroundColor: '#2a2a2a',
    alignItems: 'center', justifyContent: 'center',
  },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#ffffff' ,marginLeft:100 },
  content: { flex: 1 },
  decorativeBackground: {
    position: 'absolute', top: 0, left: 0, right: 0, height: 200, overflow: 'hidden',
  },
  decorativeCircle: { position: 'absolute', borderRadius: 50, opacity: 0.1 },
  circle1: { width: 100, height: 100, backgroundColor: '#FFD700', top: -30, right: 20 },
  circle2: { width: 80, height: 80, backgroundColor: '#00D4AA', top: 50, left: -20 },
  profileInfo: { alignItems: 'center', paddingVertical: 40, paddingHorizontal: 20 },
  profileImageContainer: { position: 'relative', marginBottom: 16 },
  profileInitial: {
    width: 100, height: 100, borderRadius: 50, backgroundColor: '#00D4AA',
    alignItems: 'center', justifyContent: 'center', borderWidth: 4, borderColor: 'black',
  },
  initialText: { fontSize: 32, fontWeight: 'bold', color: '#ffffff' },
  verifiedBadge: {
    position: 'absolute', bottom: 0, right: 0, width: 24, height: 24, borderRadius: 12,
    backgroundColor: '#00D4AA', alignItems: 'center', justifyContent: 'center',
    borderWidth: 3, borderColor: '#1a1a1a',
  },
  userName: { fontSize: 24, fontWeight: 'bold', color: '#ffffff', marginBottom: 4 },
  loadingContainer: { alignItems: 'center', paddingVertical: 40 },
  loadingText: { color: '#888888', fontSize: 16, marginTop: 12 },
  errorContainer: { alignItems: 'center', paddingVertical: 40 },
  errorText: {
    color: '#FF6B6B', fontSize: 16, textAlign: 'center', marginTop: 12, marginBottom: 20,
  },
  retryButton: {
    backgroundColor: '#00D4AA', paddingHorizontal: 20, paddingVertical: 10, borderRadius: 8,
  },
  retryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  section: { paddingHorizontal: 20, marginBottom: 30 },
  sectionTitle: { fontSize: 18, fontWeight: 'bold', color: '#ffffff', marginBottom: 16 },
  menuItem: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    paddingVertical: 16, paddingHorizontal: 16, backgroundColor: '#2a2a2a',
    borderRadius: 12, marginBottom: 8,
  },
  menuItemLeft: { flexDirection: 'row', alignItems: 'center', flex: 1 },
  menuIcon: {
    width: 36, height: 36, borderRadius: 8, alignItems: 'center', justifyContent: 'center',
    marginRight: 12,
  },
  menuText: { fontSize: 16, color: '#ffffff', fontWeight: '500' },
  menuValue: {
    fontSize: 14, color: '#bbbbbb', maxWidth: '50%', textAlign: 'right',
  },
  menuValueSmall: {
    fontSize: 12, color: '#999999', maxWidth: '50%', textAlign: 'right',
  },
  logoutButton: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center',
    paddingVertical: 16, paddingHorizontal: 20, backgroundColor: '#2a2a2a',
    borderRadius: 12, marginHorizontal: 20, marginBottom: 40, gap: 8,
  },
  logoutText: { fontSize: 16, color: '#FF6B6B', fontWeight: '600' },
});

export default ProfileScreen;