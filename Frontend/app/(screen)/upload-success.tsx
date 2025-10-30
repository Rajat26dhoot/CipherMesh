// app/(screen)/upload-success.tsx
import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { SafeAreaView } from 'react-native-safe-area-context';
import { router, useLocalSearchParams } from 'expo-router';

const UploadSuccessScreen = () => {
  const { fileKey, fileType, fileName } = useLocalSearchParams<{
    fileKey: string;
    fileType: string;
    fileName: string;
  }>();

  const handleDone = () => {
    // Navigate back to the main screen or home
    router.push('/(tabs)/home'); // or wherever you want to navigate
  };

  const handleUploadAnother = () => {
    // Navigate back to upload screen
    router.push('/(tabs)/send');
  };

  const getFileIcon = () => {
    if (fileType === 'image') return 'image';
    return 'document-text';
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        {/* Success Icon */}
        <View style={styles.successIconContainer}>
          <View style={styles.successCircle}>
            <Ionicons name="checkmark" size={40} color="#ffffff" />
          </View>
        </View>

        {/* Success Message */}
        <Text style={styles.successTitle}>Upload Successful!</Text>
        <Text style={styles.successSubtitle}>
          Your file has been uploaded successfully and is ready to share.
        </Text>

        {/* File Info */}
        <View style={styles.fileInfoContainer}>
          <View style={styles.fileIconContainer}>
            <Ionicons name={getFileIcon()} size={24} color="#00D4AA" />
          </View>
          <View style={styles.fileDetails}>
            <Text style={styles.fileName}>{fileName}</Text>
            <Text style={styles.fileKey}>File ID: {fileKey}</Text>
          </View>
        </View>

        {/* Action Buttons */}
        <View style={styles.buttonContainer}>
          <TouchableOpacity 
            style={styles.secondaryButton} 
            onPress={handleUploadAnother}
            activeOpacity={0.8}
          >
            <Ionicons name="add" size={20} color="#00D4AA" />
            <Text style={styles.secondaryButtonText}>Upload Another</Text>
          </TouchableOpacity>

          <TouchableOpacity 
            style={styles.primaryButton} 
            onPress={handleDone}
            activeOpacity={0.8}
          >
            <Text style={styles.primaryButtonText}>Done</Text>
          </TouchableOpacity>
        </View>

        {/* Additional Info */}
        <View style={styles.infoContainer}>
          <View style={styles.infoItem}>
            <Ionicons name="share" size={16} color="#666666" />
            <Text style={styles.infoText}>File is ready to share with others</Text>
          </View>
          <View style={styles.infoItem}>
            <Ionicons name="cloud-done" size={16} color="#666666" />
            <Text style={styles.infoText}>Safely stored in the cloud</Text>
          </View>
        </View>
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
    paddingHorizontal: 24,
    alignItems: 'center',
    justifyContent: 'center',
  },
  successIconContainer: {
    marginBottom: 32,
  },
  successCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#00D4AA',
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#00D4AA',
    shadowOffset: {
      width: 0,
      height: 4,
    },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  successTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ffffff',
    textAlign: 'center',
    marginBottom: 12,
  },
  successSubtitle: {
    fontSize: 16,
    color: '#888888',
    textAlign: 'center',
    lineHeight: 24,
    marginBottom: 40,
    paddingHorizontal: 20,
  },
  fileInfoContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2a2a2a',
    borderRadius: 16,
    padding: 20,
    marginBottom: 40,
    width: '100%',
    borderWidth: 1,
    borderColor: '#3a3a3a',
  },
  fileIconContainer: {
    width: 48,
    height: 48,
    borderRadius: 12,
    backgroundColor: '#1a2a2a',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 16,
  },
  fileDetails: {
    flex: 1,
  },
  fileName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#ffffff',
    marginBottom: 4,
  },
  fileKey: {
    fontSize: 14,
    color: '#666666',
  },
  buttonContainer: {
    width: '100%',
    gap: 12,
    marginBottom: 32,
  },
  primaryButton: {
    backgroundColor: '#00D4AA',
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primaryButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  secondaryButton: {
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: '#00D4AA',
  },
  secondaryButtonText: {
    color: '#00D4AA',
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 8,
  },
  infoContainer: {
    alignItems: 'center',
    gap: 12,
  },
  infoItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  infoText: {
    fontSize: 14,
    color: '#666666',
  },
});

export default UploadSuccessScreen;