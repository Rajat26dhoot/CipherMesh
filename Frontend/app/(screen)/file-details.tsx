import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Alert,
  Share,
  ScrollView,
  ActivityIndicator,
  Modal,
  Platform,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useLocalSearchParams, router } from 'expo-router';
import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import * as MediaLibrary from "expo-media-library";
import * as Sharing from "expo-sharing";
import * as Clipboard from 'expo-clipboard';
import config from '../../config';
import * as Permissions from "expo-permissions";


interface UserData {
  id: string;
  username: string;
  email: string;
  blockchainAddress: string;
  publicKey: string;
  role: string;
  createdAt: string;
  lastActive: string;
}

interface FileDetailResponse {
  success: boolean;
  message: string;
  file: {
    id: string;
    originalName: string;
    description: string;
    size: number;
    sizeFormatted: string;
    mimetype: string;
    fileType: string;
    uploadTime: string;
    downloadCount: number;
    accessCount: number;
    fileHash: string;
    ipfsHash: string;
  };
  owner: {
    userId: string;
    username: string;
    email: string;
    blockchainAddress: string;
    role: string;
    memberSince: string;
  };
  permissions: {
    total: number;
    active: number;
    expired: number;
    revoked: number;
    details: Array<{
      recipientUsername: string;
      recipientEmail: string;
      grantedTime: string;
      expirationTime: string;
      isActive: boolean;
      isExpired: boolean;
      status: string;
      accessCount: number;
    }>;
  };
  blockchain: {
    recordCount: number;
    recentActivity: Array<{
      operation: string;
      blockNumber: number;
      timestamp: string;
      transactionHash: string;
    }>;
  };
  canAccess: boolean;
  accessMethod: string;
  accessNote: string;
}

const FileDetailsScreen = () => {
  const { fileKey } = useLocalSearchParams<{ fileKey?: string }>();
  const [fileData, setFileData] = useState<FileDetailResponse | null>(null);
  const [userData, setUserData] = useState<UserData | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showAccessModal, setShowAccessModal] = useState(false);

  const fetchUserData = async (): Promise<string | null> => {
    try {
      const token = await SecureStore.getItemAsync("authToken");
      if (!token) {
        Alert.alert("Error", "No authentication token found");
        router.replace("/(auth)/welcome");
        return null;
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
          return null;
        }
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      console.log("✅ User data fetched:", data);

      if (!data.success) {
        throw new Error(data.error || "Failed to load user data");
      }

      setUserData(data.data);
      return data.data.id;
    } catch (err) {
      console.error("Error fetching user data:", err);
      Alert.alert("Error", "Failed to fetch user data");
      return null;
    }
  };

  const fetchFileDetails = useCallback(async () => {
    if (!fileKey) {
      Alert.alert('Error', 'Invalid file key');
      router.back();
      return;
    }

    setLoading(true);
    try {
      const authToken = await SecureStore.getItemAsync('authToken');
      const userId = await fetchUserData();

      if (!userId) {
        return;
      }

      const response = await fetch(
        `${config.BASE_URL}/api/file/${userId}/${fileKey}`,
        {
          method: 'GET',
          headers: {
            Authorization: authToken ? `Bearer ${authToken}` : '',
            'Content-Type': 'application/json',
          },
        }
      );

      const data = await response.json();
      console.log("DEBUG FULL RESPONSE:", JSON.stringify(data, null, 2));

      if (!response.ok || !data.success || data.canAccess === false) {
        setShowAccessModal(true);
        setLoading(false);
        return;
      }

      setFileData(data);
    } catch (error: any) {
      console.error('Fetch file details error:', error.message);
      Alert.alert('Error', error.message || 'Unable to fetch file details');
      router.back();
    } finally {
      setLoading(false);
    }
  }, [fileKey]);

  useEffect(() => {
    fetchFileDetails();
  }, [fetchFileDetails]);

  const downloadFile = async () => {
    if (!fileData || !userData) return;
    setIsDownloading(true);
  
    try {
      const authToken = await SecureStore.getItemAsync("authToken");
      const downloadUrl = `${config.BASE_URL}/api/download/${fileData.file.id}/${userData.id}`;
  
      const response = await fetch(downloadUrl, {
        headers: { Authorization: authToken ? `Bearer ${authToken}` : "" },
      });
  
      if (!response.ok) {
        Alert.alert("Error", "You do not have permission or file is missing.");
        return;
      }
  
      const blob = await response.blob();
      const reader = new FileReader();
  
      reader.onloadend = async () => {
        const base64 = (reader.result as string).split(",")[1];
        const filename = fileData.file.originalName;
        const fileUri = FileSystem.documentDirectory + filename;
  
        await FileSystem.writeAsStringAsync(fileUri, base64, {
          encoding: "base64", // ✅ FIXED HERE
        });
  
        console.log("Saved to:", fileUri);
  
        if (await Sharing.isAvailableAsync()) {
          await Sharing.shareAsync(fileUri);
        } else {
          Alert.alert("Download Complete", `File saved internally:\n${fileUri}`);
        }
      };
  
      reader.readAsDataURL(blob);
    } catch (error) {
      console.log("Download error:", error);
      Alert.alert("Download Error", "Something went wrong.");
    } finally {
      setIsDownloading(false);
    }
  };

  
  const handleRequestAccess = async () => {
    console.log("DEBUG: handleRequestAccess called");

    if (!fileKey || !userData) {
      Alert.alert("Error", "Missing file ID or user data.");
      return;
    }

    try {
      const authToken = await SecureStore.getItemAsync('authToken');

      // Try different field name combinations that backends commonly expect
      const bodyData = {
        userId: userData.id,
        fileId: fileKey,
        requesterId: userData.id,
        purpose: 'View file content',
        requestedDuration: 24,
      };

      console.log("DEBUG: Request body:", JSON.stringify(bodyData, null, 2));
      console.log("DEBUG: Auth token exists:", !!authToken);
      console.log("DEBUG: userData.id:", userData.id);
      console.log("DEBUG: fileKey:", fileKey);

      const response = await fetch(`${config.BASE_URL}/api/request-access`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(bodyData),
      });

      const data = await response.json();
      console.log("DEBUG: Response status:", response.status);
      console.log("DEBUG: Response:", JSON.stringify(data, null, 2));

      if (response.ok && data.success) {
        Alert.alert('Request Sent', 'Your access request has been sent to the file owner.');
        setShowAccessModal(false);
        router.back();
      } else {
        Alert.alert('Error', data.error || data.message || 'Failed to send request.');
      }
    } catch (err) {
      console.error("DEBUG: Error in handleRequestAccess:", err);
      Alert.alert('Error', 'Something went wrong while sending request.');
    }
  };

  const shareFile = async () => {
    if (!fileData) return;
    try {
      await Share.share({
        message: `File: ${fileData.file.originalName}\nSize: ${fileData.file.sizeFormatted}\nUploaded: ${new Date(
          fileData.file.uploadTime
        ).toLocaleString()}\n\nFile ID: ${fileKey}`,
        title: 'File Information',
      });
    } catch (error) {
      console.error('Error sharing:', error);
    }
  };

  const copyKey = async () => {
    try {
      await Clipboard.setStringAsync(fileKey as string);
      Alert.alert('Copied!', 'File ID copied to clipboard');
    } catch {
      Alert.alert('Error', 'Failed to copy ID');
    }
  };

  const navigateToGrantAccess = () => {
    if (!fileData) return;
    router.push({
      pathname: '/(screen)/grant-access',
      params: { fileId: fileData.file.id.trim(), fileName: fileData.file.originalName, fileKey },
    });
  };

  if (loading) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#00D4AA" />
          <Text style={styles.loadingText}>Loading file information...</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (showAccessModal) {
    return (
      <Modal transparent animationType="fade">
        <View style={styles.modalOverlay}>
          <View style={styles.modalBox}>
            <Ionicons name="lock-closed" size={48} color="#00D4AA" style={{ marginBottom: 12 }} />
            <Text style={styles.modalTitle}>Access Restricted</Text>
            <Text style={styles.modalMessage}>
              You don't have permission to view this file. Would you like to request access?
            </Text>

            <TouchableOpacity style={styles.modalPrimaryBtn} onPress={handleRequestAccess}>
              <Text style={styles.modalPrimaryText}>Request Access</Text>
            </TouchableOpacity>

            <TouchableOpacity style={styles.modalSecondaryBtn} onPress={() => router.back()}>
              <Text style={styles.modalSecondaryText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    );
  }

  if (!fileData) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.loadingContainer}>
          <Text style={styles.loadingText}>No file data available</Text>
          <TouchableOpacity style={styles.retryButton} onPress={fetchFileDetails}>
            <Text style={styles.retryButtonText}>Retry</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity 
          style={styles.backButton} 
          onPress={() => router.back()}
          activeOpacity={0.7}
        >
          <Ionicons name="arrow-back" size={24} color="#ffffff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>File Details</Text>
      </View>

      <ScrollView 
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.fileContainer}>
          <View style={styles.fileIconContainer}>
            <Ionicons 
              name={fileData.file.fileType === 'Image' ? 'image' : 'document-text'} 
              size={60} 
              color="#00D4AA" 
            />
          </View>
          
          <Text style={styles.fileName}>{fileData.file.originalName}</Text>
          <Text style={styles.fileSize}>{fileData.file.sizeFormatted}</Text>
          {fileData.file.description && (
            <Text style={styles.fileDescription}>{fileData.file.description}</Text>
          )}
        </View>

        <View style={styles.keySection}>
          <Text style={styles.sectionTitle}>File ID</Text>
          <View style={styles.keyContainer}>
            <Text style={styles.keyText} numberOfLines={1} ellipsizeMode="middle">
              {fileData.file.id}
            </Text>
            <TouchableOpacity 
              style={styles.copyButton} 
              onPress={copyKey}
              activeOpacity={0.7}
            >
              <Ionicons name="copy-outline" size={18} color="#00D4AA" />
            </TouchableOpacity>
          </View>
        </View>

        <View style={styles.detailsSection}>
          <Text style={styles.sectionTitle}>File Information</Text>
          
          <View style={styles.infoCard}>
            <View style={styles.infoRow}>
              <Ionicons name="time" size={20} color="#666666" />
              <View style={styles.infoContent}>
                <Text style={styles.infoLabel}>Upload Date</Text>
                <Text style={styles.infoValue}>
                  {new Date(fileData.file.uploadTime).toLocaleString()}
                </Text>
              </View>
            </View>

            <View style={styles.infoRow}>
              <Ionicons name="download" size={20} color="#666666" />
              <View style={styles.infoContent}>
                <Text style={styles.infoLabel}>Downloads</Text>
                <Text style={styles.infoValue}>{fileData.file.downloadCount}</Text>
              </View>
            </View>

            <View style={styles.infoRow}>
              <Ionicons name="eye" size={20} color="#666666" />
              <View style={styles.infoContent}>
                <Text style={styles.infoLabel}>Access Count</Text>
                <Text style={styles.infoValue}>{fileData.file.accessCount}</Text>
              </View>
            </View>
          </View>
        </View>

        <View style={styles.detailsSection}>
          <Text style={styles.sectionTitle}>Owner Information</Text>
          
          <View style={styles.infoCard}>
            <View style={styles.infoRow}>
              <Ionicons name="person" size={20} color="#666666" />
              <View style={styles.infoContent}>
                <Text style={styles.infoLabel}>Username</Text>
                <Text style={styles.infoValue}>{fileData.owner.username}</Text>
              </View>
            </View>

            <View style={styles.infoRow}>
              <Ionicons name="mail" size={20} color="#666666" />
              <View style={styles.infoContent}>
                <Text style={styles.infoLabel}>Email</Text>
                <Text style={styles.infoValue}>{fileData.owner.email}</Text>
              </View>
            </View>

            <View style={styles.infoRow}>
              <Ionicons name="wallet" size={20} color="#666666" />
              <View style={styles.infoContent}>
                <Text style={styles.infoLabel}>Blockchain Address</Text>
                <Text style={styles.infoValue} numberOfLines={1} ellipsizeMode="middle">
                  {fileData.owner.blockchainAddress}
                </Text>
              </View>
            </View>
          </View>
        </View>

        <View style={styles.detailsSection}>
          <Text style={styles.sectionTitle}>Permissions ({fileData.permissions.active} Active)</Text>
          
          <View style={styles.infoCard}>
            {fileData.permissions.details.length > 0 ? (
              fileData.permissions.details.map((perm, index) => (
                <View key={index} style={[styles.permissionItem, index > 0 && styles.permissionItemBorder]}>
                  <View style={styles.permissionHeader}>
                    <Text style={styles.permissionUsername}>{perm.recipientUsername}</Text>
                    <View style={[
                      styles.statusBadge,
                      { backgroundColor: perm.isActive ? '#00D4AA20' : '#66666620' }
                    ]}>
                      <Text style={[
                        styles.statusText,
                        { color: perm.isActive ? '#00D4AA' : '#666666' }
                      ]}>
                        {perm.status}
                      </Text>
                    </View>
                  </View>
                  <Text style={styles.permissionEmail}>{perm.recipientEmail}</Text>
                  <Text style={styles.permissionDate}>
                    Granted: {new Date(perm.grantedTime).toLocaleString()}
                  </Text>
                  {perm.expirationTime && (
                    <Text style={styles.permissionDate}>
                      Expires: {new Date(perm.expirationTime).toLocaleString()}
                    </Text>
                  )}
                  <Text style={styles.permissionAccess}>
                    Access Count: {perm.accessCount}
                  </Text>
                </View>
              ))
            ) : (
              <Text style={styles.emptyText}>No permissions granted</Text>
            )}
          </View>
        </View>

        <View style={styles.detailsSection}>
          <Text style={styles.sectionTitle}>Blockchain Activity</Text>
          
          <View style={styles.infoCard}>
            <Text style={styles.blockchainCount}>
              Total Records: {fileData.blockchain.recordCount}
            </Text>
            {fileData.blockchain.recentActivity.map((activity, index) => (
              <View key={index} style={[styles.activityItem, index > 0 && styles.activityItemBorder]}>
                <View style={styles.activityHeader}>
                  <Ionicons name="cube" size={16} color="#00D4AA" />
                  <Text style={styles.activityOperation}>{activity.operation}</Text>
                </View>
                <Text style={styles.activityDetail}>
                  Block: #{activity.blockNumber}
                </Text>
                <Text style={styles.activityDetail}>
                  Time: {new Date(activity.timestamp).toLocaleString()}
                </Text>
                <Text style={styles.activityHash} numberOfLines={1} ellipsizeMode="middle">
                  TX: {activity.transactionHash}
                </Text>
              </View>
            ))}
          </View>
        </View>

        <View style={styles.actionsSection}>
          <TouchableOpacity 
            style={styles.downloadButton} 
            onPress={downloadFile}
            activeOpacity={0.8}
            disabled={isDownloading || !fileData.canAccess}
          >
            <Ionicons 
              name={isDownloading ? "hourglass-outline" : "download"} 
              size={20} 
              color="#ffffff" 
            />
            <Text style={styles.downloadButtonText}>
              {isDownloading ? "Downloading..." : "Download File"}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity 
            style={styles.shareButton} 
            onPress={shareFile}
            activeOpacity={0.8}
          >
            <Ionicons name="share-outline" size={20} color="#00D4AA" />
            <Text style={styles.shareButtonText}>Share Details</Text>
          </TouchableOpacity>

          <TouchableOpacity 
            style={styles.grantAccessButton} 
            onPress={navigateToGrantAccess}
            activeOpacity={0.8}
          >
            <Ionicons name="people" size={20} color="#ffffff" />
            <Text style={styles.grantAccessButtonText}>Grant Access to Users</Text>
          </TouchableOpacity>
        </View>

        <View style={styles.warningSection}>
          <Ionicons name="shield-checkmark" size={16} color="#00D4AA" />
          <Text style={styles.warningText}>
            {fileData.accessNote}
          </Text>
        </View>

        <View style={styles.spacer} />
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
  },
  loadingContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  loadingText: {
    fontSize: 16,
    color: '#666666',
    marginTop: 16,
  },
  retryButton: {
    marginTop: 20,
    backgroundColor: '#00D4AA',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 8,
  },
  retryButtonText: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '600',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#333333',
  },
  backButton: {
    padding: 8,
    marginRight: 12,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#ffffff',
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: 24,
    paddingTop: 32,
    paddingBottom: 20,
  },
  fileContainer: {
    alignItems: 'center',
    marginBottom: 40,
    backgroundColor: '#242424',
    borderRadius: 16,
    padding: 32,
  },
  fileIconContainer: {
    backgroundColor: '#333333',
    padding: 20,
    borderRadius: 50,
    marginBottom: 16,
  },
  fileName: {
    fontSize: 18,
    fontWeight: '600',
    color: '#ffffff',
    textAlign: 'center',
    marginBottom: 4,
  },
  fileSize: {
    fontSize: 14,
    color: '#888888',
  },
  fileDescription: {
    fontSize: 14,
    color: '#00D4AA',
    textAlign: 'center',
    marginTop: 8,
    fontStyle: 'italic',
  },
  keySection: {
    marginBottom: 32,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#ffffff',
    marginBottom: 16,
  },
  keyContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    borderColor: '#00D4AA',
  },
  keyText: {
    flex: 1,
    fontSize: 12,
    fontWeight: 'bold',
    color: '#00D4AA',
    fontFamily: 'monospace',
  },
  copyButton: {
    padding: 8,
    backgroundColor: '#333333',
    borderRadius: 6,
    marginLeft: 8,
  },
  detailsSection: {
    marginBottom: 32,
  },
  infoCard: {
    backgroundColor: '#242424',
    borderRadius: 12,
    padding: 20,
  },
  infoRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  infoContent: {
    marginLeft: 12,
    flex: 1,
  },
  infoLabel: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 2,
  },
  infoValue: {
    fontSize: 14,
    color: '#ffffff',
    fontWeight: '500',
  },
  permissionItem: {
    paddingVertical: 12,
  },
  permissionItemBorder: {
    borderTopWidth: 1,
    borderTopColor: '#333333',
  },
  permissionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  permissionUsername: {
    fontSize: 15,
    fontWeight: '600',
    color: '#ffffff',
  },
  statusBadge: {
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 6,
  },
  statusText: {
    fontSize: 11,
    fontWeight: '600',
    textTransform: 'uppercase',
  },
  permissionEmail: {
    fontSize: 13,
    color: '#888888',
    marginBottom: 6,
  },
  permissionDate: {
    fontSize: 12,
    color: '#666666',
    marginBottom: 2,
  },
  permissionAccess: {
    fontSize: 12,
    color: '#00D4AA',
    marginTop: 4,
  },
  emptyText: {
    color: '#666666',
    textAlign: 'center',
    fontSize: 14,
  },
  blockchainCount: {
    fontSize: 14,
    color: '#00D4AA',
    fontWeight: '600',
    marginBottom: 12,
  },
  activityItem: {
    paddingVertical: 12,
  },
  activityItemBorder: {
    borderTopWidth: 1,
    borderTopColor: '#333333',
  },
  activityHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
  },
  activityOperation: {
    fontSize: 14,
    fontWeight: '600',
    color: '#ffffff',
    marginLeft: 8,
  },
  activityDetail: {
    fontSize: 12,
    color: '#888888',
    marginBottom: 2,
  },
  activityHash: {
    fontSize: 11,
    color: '#666666',
    fontFamily: 'monospace',
    marginTop: 4,
  },
  actionsSection: {
    marginBottom: 24,
    gap: 12,
  },
  downloadButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#00D4AA',
    paddingVertical: 16,
    borderRadius: 12,
    gap: 8,
  },
  downloadButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  shareButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#333333',
    paddingVertical: 16,
    borderRadius: 12,
    gap: 8,
  },
  shareButtonText: {
    color: '#00D4AA',
    fontSize: 16,
    fontWeight: '600',
  },
  grantAccessButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#4A90E2',
    paddingVertical: 16,
    borderRadius: 12,
    gap: 8,
  },
  grantAccessButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  warningSection: {
    flexDirection: 'row',
    backgroundColor: '#1a2a1a',
    padding: 16,
    borderRadius: 8,
    borderLeftWidth: 3,
    borderLeftColor: '#00D4AA',
    alignItems: 'flex-start',
  },
  warningText: {
    color: '#00D4AA',
    fontSize: 12,
    marginLeft: 8,
    flex: 1,
    lineHeight: 16,
  },
  spacer: {
    height: 40,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.7)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalBox: {
    width: '80%',
    backgroundColor: '#242424',
    padding: 24,
    borderRadius: 12,
    alignItems: 'center',
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#ffffff',
    marginBottom: 8,
  },
  modalMessage: {
    fontSize: 14,
    color: '#aaaaaa',
    textAlign: 'center',
    marginBottom: 20,
  },
  modalPrimaryBtn: {
    backgroundColor: '#00D4AA',
    paddingVertical: 12,
    width: '100%',
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 10,
  },
  modalPrimaryText: {
    color: '#ffffff',
    fontWeight: '600',
  },
  modalSecondaryBtn: {
    paddingVertical: 12,
    width: '100%',
    borderRadius: 8,
    alignItems: 'center',
    backgroundColor: '#333333',
  },
  modalSecondaryText: {
    color: '#00D4AA',
    fontWeight: '600',
  },  
});

export default FileDetailsScreen;