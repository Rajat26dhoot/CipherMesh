import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  TextInput,
  ScrollView,
  ActivityIndicator,
  Alert,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useLocalSearchParams, router } from 'expo-router';
import * as SecureStore from 'expo-secure-store';
import config from '../../config'; 
interface User {
  _id: string;
  username: string;
  email: string;
  blockchainAddress?: string;
}

const DURATION_PRESETS = [
  { label: '1 Hour', value: 1 },
  { label: '6 Hours', value: 6 },
  { label: '24 Hours', value: 24 },
  { label: '7 Days', value: 168 },
  { label: '30 Days', value: 720 },
];

const GrantAccessScreen = () => {
  const params = useLocalSearchParams();
  
  // FIXED: Properly extract and validate params
  const fileId = (params.fileId || params.fileKey) as string;
  const fileName = params.fileName as string;
  
  // Debug logging on mount
  useEffect(() => {
    console.log('=== GrantAccessScreen Mounted ===');
    console.log('All params:', params);
    console.log('Extracted fileId:', fileId);
    console.log('Extracted fileName:', fileName);
    console.log('fileId type:', typeof fileId);
    console.log('fileId exists:', !!fileId);
    console.log('================================');
  }, []);
  
  const [users, setUsers] = useState<User[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [durationHours, setDurationHours] = useState('24');
  const [selectedPreset, setSelectedPreset] = useState(24);
  const [purpose, setPurpose] = useState('');
  const [grantingAccessTo, setGrantingAccessTo] = useState<string | null>(null);

  useEffect(() => {
    fetchAllUsers();
  }, []);

  const fetchAllUsers = async () => {
    setLoadingUsers(true);
    try {
      const authToken = await SecureStore.getItemAsync('authToken');
      const currentUserId = await SecureStore.getItemAsync('userId');
  
      const response = await fetch(`${config.BASE_URL}/api/users`, {
        method: 'GET',
        headers: {
          Authorization: authToken ? `Bearer ${authToken}` : '',
          'Content-Type': 'application/json',
        },
      });
  
      const data = await response.json();
  
      if (!response.ok || data.success === false) {
        throw new Error(data?.message || 'Failed to fetch users');
      }
  
      const filteredUsers =
        data.users
          ?.filter((user: any) => user.id !== currentUserId) // filter current user
          .map((u: any) => ({
            ...u,
            _id: u._id || u.id, // 🔥 normalize so every user has _id
          })) || [];
  
      console.log('✅ Normalized Users:', filteredUsers);
  
      setUsers(filteredUsers);
    } catch (error: any) {
      console.error('Fetch users error:', error.message);
      Alert.alert('Error', error.message || 'Unable to fetch users');
    } finally {
      setLoadingUsers(false);
    }
  };
  

  const handleGrantAccess = async (recipientId: string, recipientName: string) => {
    // Validation checks
    if (!purpose.trim()) {
      Alert.alert('Required Field', 'Please enter a purpose for sharing this file.');
      return;
    }

    if (!fileId || fileId === 'undefined') {
      console.error('=== File ID Validation Failed ===');
      console.error('fileId value:', fileId);
      console.error('fileId type:', typeof fileId);
      console.error('All params:', params);
      console.error('================================');
      
      Alert.alert('Error', 'File ID is missing. Please go back and try again.');
      return;
    }

    setGrantingAccessTo(recipientId);

    try {
      const authToken = await SecureStore.getItemAsync('authToken');
      const ownerId = await SecureStore.getItemAsync('userId');
      console.log(ownerId);

      if (!authToken || !ownerId) {
        throw new Error('Authentication required. Please log in again.');
      }

      if (!ownerId || !recipientId || !fileId) {
        console.error('Missing required field(s):', { ownerId, recipientId, fileId });
        Alert.alert('Error', 'Missing user or file information. Please try again.');
        setGrantingAccessTo(null);
        return;
      }

      const requestBody = {
        ownerId: ownerId.trim(),
        recipientId: recipientId.trim(),
        fileId: fileId.trim(),
        durationHours: parseInt(durationHours) || 24,
        purpose: purpose.trim(),
      };

      console.log('=== Grant Access Request ===');
      console.log('Owner ID:', requestBody.ownerId);
      console.log('Owner ID length:', requestBody.ownerId.length);
      console.log('Recipient ID:', requestBody.recipientId);
      console.log('Recipient ID length:', requestBody.recipientId.length);
      console.log('File ID:', requestBody.fileId);
      console.log('File ID length:', requestBody.fileId.length);
      console.log('Duration:', requestBody.durationHours);
      console.log('Purpose:', requestBody.purpose);
      console.log('Full Body:', JSON.stringify(requestBody, null, 2));
      console.log('===========================');

      const response = await fetch(`${config.BASE_URL}/api/grant-access`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      const data = await response.json();
      
      console.log('=== Grant Access Response ===');
      console.log('Status:', response.status);
      console.log('Response:', JSON.stringify(data, null, 2));
      console.log('============================');

      if (!response.ok || data.success === false) {
        throw new Error(data?.message || data?.error || 'Failed to grant access');
      }

      Alert.alert(
        'Success! 🎉',
        `Access granted to ${recipientName} for ${durationHours} hours.`,
        [
          { 
            text: 'OK', 
            onPress: () => router.back()
          }
        ]
      );
    } catch (error: any) {
      console.error('=== Grant Access Error ===');
      console.error('Error:', error);
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
      console.error('========================');
      
      Alert.alert(
        'Error', 
        error.message || 'Failed to grant access. Please try again.'
      );
    } finally {
      setGrantingAccessTo(null);
    }
  };

  const handlePresetSelect = (hours: number) => {
    setSelectedPreset(hours);
    setDurationHours(hours.toString());
  };

  const handleGoBack = () => {
    router.back();
  };

  const filteredUsers = users.filter(
    (user) =>
      user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity 
          style={styles.backButton} 
          onPress={handleGoBack}
          activeOpacity={0.7}
        >
          <Ionicons name="arrow-back" size={24} color="#ffffff" />
        </TouchableOpacity>
        <View style={styles.headerContent}>
          <Text style={styles.headerTitle}>Grant Access</Text>
          {fileName && (
            <Text style={styles.headerSubtitle} numberOfLines={1}>
              {fileName}
            </Text>
          )}
        </View>
      </View>

      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.keyboardView}
      >
        <ScrollView
          style={styles.scrollView}
          contentContainerStyle={styles.scrollContent}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          {/* Settings Section */}
          <View style={styles.settingsSection}>
            <View style={styles.sectionHeader}>
              <Ionicons name="settings-outline" size={20} color="#00D4AA" />
              <Text style={styles.sectionTitle}>Access Settings</Text>
            </View>

            {/* Duration Presets */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>Duration</Text>
              <View style={styles.presetContainer}>
                {DURATION_PRESETS.map((preset) => (
                  <TouchableOpacity
                    key={preset.value}
                    style={[
                      styles.presetButton,
                      selectedPreset === preset.value && styles.presetButtonActive,
                    ]}
                    onPress={() => handlePresetSelect(preset.value)}
                    activeOpacity={0.7}
                  >
                    <Text
                      style={[
                        styles.presetButtonText,
                        selectedPreset === preset.value &&
                          styles.presetButtonTextActive,
                      ]}
                    >
                      {preset.label}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>

              {/* Custom Duration Input */}
              <View style={styles.customDurationContainer}>
                <Text style={styles.customDurationLabel}>Or enter custom hours:</Text>
                <TextInput
                  style={styles.customInput}
                  value={durationHours}
                  onChangeText={(text) => {
                    setDurationHours(text);
                    setSelectedPreset(parseInt(text) || 0);
                  }}
                  keyboardType="numeric"
                  placeholder="24"
                  placeholderTextColor="#666666"
                />
              </View>
            </View>

            {/* Purpose Input */}
            <View style={styles.inputGroup}>
              <Text style={styles.inputLabel}>
                Purpose <Text style={styles.requiredMark}>*</Text>
              </Text>
              <TextInput
                style={[styles.input, styles.textArea]}
                value={purpose}
                onChangeText={setPurpose}
                placeholder="e.g., Project collaboration, Review, etc."
                placeholderTextColor="#666666"
                multiline
                numberOfLines={3}
                textAlignVertical="top"
              />
              {purpose.trim().length === 0 && (
                <Text style={styles.helperText}>
                  Please describe why you're sharing this file
                </Text>
              )}
            </View>
          </View>

          {/* Search Section */}
          <View style={styles.searchSection}>
            <View style={styles.sectionHeader}>
              <Ionicons name="people-outline" size={20} color="#00D4AA" />
              <Text style={styles.sectionTitle}>Select User</Text>
            </View>

            <View style={styles.searchContainer}>
              <Ionicons name="search" size={20} color="#666666" />
              <TextInput
                style={styles.searchInput}
                value={searchQuery}
                onChangeText={setSearchQuery}
                placeholder="Search by name or email..."
                placeholderTextColor="#666666"
              />
              {searchQuery.length > 0 && (
                <TouchableOpacity
                  onPress={() => setSearchQuery('')}
                  style={styles.clearButton}
                >
                  <Ionicons name="close-circle" size={20} color="#666666" />
                </TouchableOpacity>
              )}
            </View>

            {/* User Count Badge */}
            {!loadingUsers && (
              <View style={styles.userCountBadge}>
                <Ionicons name="people" size={14} color="#00D4AA" />
                <Text style={styles.userCountText}>
                  {filteredUsers.length} user{filteredUsers.length !== 1 ? 's' : ''} found
                </Text>
              </View>
            )}
          </View>

          {/* Users List */}
          {loadingUsers ? (
            <View style={styles.loadingContainer}>
              <ActivityIndicator size="large" color="#00D4AA" />
              <Text style={styles.loadingText}>Loading users...</Text>
            </View>
          ) : (
            <View style={styles.userListContainer}>
              {filteredUsers.length > 0 ? (
                filteredUsers.map((user, index) => (
                  <TouchableOpacity
                    key={user._id || `user-${index}`}
                    style={styles.userItem}
                    onPress={() => handleGrantAccess(user._id, user.username)}
                    disabled={grantingAccessTo === user._id}
                    activeOpacity={0.7}
                  >
                    <View style={styles.userInfo}>
                      <View style={styles.userAvatar}>
                        <Text style={styles.avatarText}>
                          {user.username.charAt(0).toUpperCase()}
                        </Text>
                      </View>
                      <View style={styles.userDetails}>
                        <Text style={styles.userName}>{user.username}</Text>
                        <Text style={styles.userEmail}>{user.email}</Text>
                      </View>
                    </View>
                    <View
                      style={[
                        styles.grantButton,
                        grantingAccessTo === user._id &&
                          styles.grantButtonDisabled,
                      ]}
                    >
                      {grantingAccessTo === user._id ? (
                        <ActivityIndicator size="small" color="#ffffff" />
                      ) : (
                        <>
                          <Ionicons name="checkmark" size={18} color="#ffffff" />
                          <Text style={styles.grantButtonText}>Grant</Text>
                        </>
                      )}
                    </View>
                  </TouchableOpacity>
                ))
              ) : (
                <View style={styles.emptyContainer}>
                  <View style={styles.emptyIconContainer}>
                    <Ionicons name="people-outline" size={48} color="#666666" />
                  </View>
                  <Text style={styles.emptyTitle}>
                    {searchQuery ? 'No Results' : 'No Users Available'}
                  </Text>
                  <Text style={styles.emptyText}>
                    {searchQuery
                      ? 'Try adjusting your search terms'
                      : 'There are no other users in the system'}
                  </Text>
                </View>
              )}
            </View>
          )}
        </ScrollView>
      </KeyboardAvoidingView>
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
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2a2a',
  },
  backButton: {
    padding: 8,
    marginRight: 12,
  },
  headerContent: {
    flex: 1,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#ffffff',
  },
  headerSubtitle: {
    fontSize: 13,
    color: '#888888',
    marginTop: 2,
  },
  keyboardView: {
    flex: 1,
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingBottom: 24,
  },
  settingsSection: {
    paddingHorizontal: 24,
    paddingVertical: 20,
    borderBottomWidth: 1,
    borderBottomColor: '#2a2a2a',
  },
  sectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 16,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#ffffff',
  },
  inputGroup: {
    marginBottom: 20,
  },
  inputLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#cccccc',
    marginBottom: 10,
  },
  requiredMark: {
    color: '#ff6b6b',
  },
  presetContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 12,
  },
  presetButton: {
    paddingHorizontal: 16,
    paddingVertical: 10,
    borderRadius: 10,
    backgroundColor: '#242424',
    borderWidth: 1.5,
    borderColor: '#333333',
  },
  presetButtonActive: {
    backgroundColor: '#00D4AA15',
    borderColor: '#00D4AA',
  },
  presetButtonText: {
    fontSize: 13,
    fontWeight: '600',
    color: '#888888',
  },
  presetButtonTextActive: {
    color: '#00D4AA',
  },
  customDurationContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  customDurationLabel: {
    fontSize: 13,
    color: '#888888',
    flex: 1,
  },
  customInput: {
    backgroundColor: '#242424',
    borderRadius: 10,
    paddingHorizontal: 16,
    paddingVertical: 10,
    fontSize: 14,
    color: '#ffffff',
    borderWidth: 1.5,
    borderColor: '#333333',
    width: 80,
    textAlign: 'center',
  },
  input: {
    backgroundColor: '#242424',
    borderRadius: 10,
    paddingHorizontal: 16,
    paddingVertical: 12,
    fontSize: 14,
    color: '#ffffff',
    borderWidth: 1.5,
    borderColor: '#333333',
  },
  textArea: {
    minHeight: 80,
    paddingTop: 12,
  },
  helperText: {
    fontSize: 12,
    color: '#666666',
    marginTop: 6,
    fontStyle: 'italic',
  },
  searchSection: {
    paddingHorizontal: 24,
    paddingVertical: 20,
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#242424',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderRadius: 12,
    gap: 10,
    borderWidth: 1.5,
    borderColor: '#333333',
  },
  searchInput: {
    flex: 1,
    fontSize: 14,
    color: '#ffffff',
  },
  clearButton: {
    padding: 4,
  },
  userCountBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginTop: 12,
    paddingHorizontal: 12,
    paddingVertical: 6,
    backgroundColor: '#00D4AA10',
    alignSelf: 'flex-start',
    borderRadius: 8,
  },
  userCountText: {
    fontSize: 12,
    color: '#00D4AA',
    fontWeight: '600',
  },
  loadingContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 60,
  },
  loadingText: {
    fontSize: 14,
    color: '#888888',
    marginTop: 12,
  },
  userListContainer: {
    paddingHorizontal: 24,
  },
  userItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#242424',
    padding: 16,
    borderRadius: 14,
    marginBottom: 12,
    borderWidth: 1.5,
    borderColor: '#2a2a2a',
  },
  userInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
    marginRight: 12,
  },
  userAvatar: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: '#00D4AA20',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
    borderWidth: 2,
    borderColor: '#00D4AA40',
  },
  avatarText: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#00D4AA',
  },
  userDetails: {
    flex: 1,
  },
  userName: {
    fontSize: 15,
    fontWeight: '600',
    color: '#ffffff',
    marginBottom: 3,
  },
  userEmail: {
    fontSize: 13,
    color: '#888888',
  },
  grantButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#00D4AA',
    paddingHorizontal: 18,
    paddingVertical: 10,
    borderRadius: 10,
    gap: 6,
    minWidth: 90,
    justifyContent: 'center',
  },
  grantButtonDisabled: {
    backgroundColor: '#666666',
  },
  grantButtonText: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '700',
  },
  emptyContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 60,
    paddingHorizontal: 40,
  },
  emptyIconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#242424',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 16,
  },
  emptyTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#ffffff',
    marginBottom: 8,
  },
  emptyText: {
    color: '#888888',
    textAlign: 'center',
    fontSize: 14,
    lineHeight: 20,
  },
});

export default GrantAccessScreen;