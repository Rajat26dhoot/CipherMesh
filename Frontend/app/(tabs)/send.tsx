// app/(tabs)/send.tsx
import React, { useState } from 'react';
import { 
  View, 
  Text, 
  StyleSheet, 
  TouchableOpacity, 
  Alert, 
  ScrollView, 
  TextInput, 
  ActivityIndicator 
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { SafeAreaView } from "react-native-safe-area-context";
import * as ImagePicker from 'expo-image-picker';
import * as DocumentPicker from 'expo-document-picker';
import * as SecureStore from 'expo-secure-store';
import { router } from 'expo-router';
import config from '../../config'; 
interface SelectedFile {
  uri: string;
  type: 'image' | 'document';
  name: string;
  size?: number;
  mimeType?: string;
}

const SendScreen = () => {
  const [selectedFile, setSelectedFile] = useState<SelectedFile | null>(null);
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [isPublic, setIsPublic] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  // Replace with your actual base URL
  const BASE_URL = `${config.BASE_URL}`; // Update this to your API base URL

  const pickDocument = async () => {
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: ['application/pdf', 'image/*', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        copyToCacheDirectory: false,
        multiple: false,
      });

      console.log('Document picker result:', result);

      if (result.canceled) {
        console.log('Document selection was canceled');
        return;
      }

      if (result.assets && result.assets.length > 0) {
        const asset = result.assets[0];
        console.log('Selected asset:', asset);
        
        const fileData: SelectedFile = {
          uri: asset.uri,
          type: (asset.mimeType?.startsWith('image/') ? 'image' : 'document') as 'image' | 'document',
          name: asset.name,
          size: asset.size,
          mimeType: asset.mimeType,
        };

        setSelectedFile(fileData);
        console.log('File set successfully:', fileData);
      }
    } catch (error) {
      console.error('Document picker error:', error);
      Alert.alert("Error", "Failed to pick document");
    }
  };

  const takePhoto = async () => {
    try {
      // Request camera permission
      const permissionResult = await ImagePicker.requestCameraPermissionsAsync();
      
      if (permissionResult.granted === false) {
        Alert.alert("Permission Required", "Permission to access camera is required!");
        return;
      }

      // Launch camera
      const result = await ImagePicker.launchCameraAsync({
        mediaTypes: ImagePicker.MediaTypeOptions.Images,
        allowsEditing: true,
        aspect: [4, 3],
        quality: 0.8,
      });

      console.log('Camera result:', result);

      if (!result.canceled && result.assets && result.assets.length > 0) {
        const asset = result.assets[0];
        const fileData: SelectedFile = {
          uri: asset.uri,
          type: 'image' as const,
          name: `photo_${Date.now()}.jpg`,
          size: asset.fileSize,
          mimeType: asset.mimeType || 'image/jpeg',
        };

        setSelectedFile(fileData);
        console.log('Photo set successfully:', fileData);
      }
    } catch (error) {
      console.error('Camera error:', error);
      Alert.alert("Error", "Failed to take photo");
    }
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return 'Unknown size';
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const parseTags = (tagsString: string): string[] => {
    return tagsString
      .split(',')
      .map(tag => tag.trim())
      .filter(tag => tag.length > 0);
  };

  const generateFileKey = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 4; j++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      if (i < 2) result += '-';
    }
    return result;
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      Alert.alert("Required", "Please select a file to continue.");
      return;
    }
  
    try {
      setUploading(true);
      setUploadProgress(0);
  
      // Get auth token and userId
      const authToken = await SecureStore.getItemAsync('authToken');
      const userId = await SecureStore.getItemAsync('userId');
  
      if (!authToken || !userId) {
        Alert.alert('Error', 'Please login first');
        router.push('/(auth)/welcome');
        return;
      }
  
      // Create FormData
      const formData = new FormData();
  
      // Add file
      formData.append('file', {
        uri: selectedFile.uri,
        name: selectedFile.name,
        type: selectedFile.mimeType || (selectedFile.type === 'image' ? 'image/jpeg' : 'application/pdf'),
      } as any);
  
      // Add other fields
      formData.append('description', description.trim() || 'No description provided');
      formData.append('userId', userId);
      if (tags.trim()) {
        formData.append('tags', JSON.stringify(parseTags(tags)));
      }
      formData.append('isPublic', isPublic.toString());
  
      console.log('Uploading file:', {
        name: selectedFile.name,
        type: selectedFile.mimeType,
        description: description.trim(),
        tags: tags.trim() ? parseTags(tags) : [],
        isPublic,
        userId,
      });
  
      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);
  
      const response = await fetch(`${BASE_URL}/api/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`, // optional, if backend uses auth
        },
        body: formData,
      });
  
      clearInterval(progressInterval);
      setUploadProgress(100);
  
      const data = await response.json();
      console.log('Upload response:', data);
  
      if (!response.ok || data.success === false) {
        throw new Error(data?.error || data?.message || 'Upload failed');
      }
  
      // Navigate to success screen
      const fileKey = data?.file?.id || generateFileKey();
      router.push({
        pathname: '/(screen)/upload-success',
        params: {
          fileKey,
          fileType: selectedFile.type,
          fileName: selectedFile.name,
        },
      });
  
      // Reset form
      setSelectedFile(null);
      setDescription('');
      setTags('');
      setIsPublic(true);
  
    } catch (error: any) {
      console.error('Upload error:', error.message);
      Alert.alert('Upload Failed', error.message || 'Something went wrong during upload');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };
  

  const getFileDisplayInfo = () => {
    if (!selectedFile) return null;
    
    if (selectedFile.type === 'document') {
      return {
        icon: 'document-text',
        text: selectedFile.name,
        subtext: selectedFile.size ? formatFileSize(selectedFile.size) : ''
      };
    } else {
      return {
        icon: 'image',
        text: selectedFile.name,
        subtext: selectedFile.size ? formatFileSize(selectedFile.size) : ''
      };
    }
  };

  const clearSelection = () => {
    setSelectedFile(null);
  };

  return (
    <SafeAreaView style={styles.container}  edges={['top']}>
      <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
        <Text style={styles.title}>Upload your file</Text>
        <View style={styles.titleRow}>
          <Text style={styles.title}>and share with others </Text>
          <Ionicons name="share" size={24} color="#ffffff" />
        </View>
        
        <Text style={styles.subtitle}>
          Upload documents, images to share with others. Add details to make your files easier to find.
        </Text>

        {/* File Selection */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Select File</Text>
          
          <TouchableOpacity 
            style={styles.uploadContainer} 
            onPress={selectedFile ? clearSelection : pickDocument}
            activeOpacity={0.7}
          >
            <View style={styles.uploadBox}>
              {selectedFile ? (
                <View style={styles.selectedFileContainer}>
                  <Ionicons 
                    name={getFileDisplayInfo()?.icon as any} 
                    size={40} 
                    color="#00D4AA" 
                  />
                  <Text style={styles.selectedFileText}>
                    {getFileDisplayInfo()?.text}
                  </Text>
                  {getFileDisplayInfo()?.subtext && (
                    <Text style={styles.selectedFileSubtext}>
                      {getFileDisplayInfo()?.subtext}
                    </Text>
                  )}
                  <TouchableOpacity style={styles.changeFileButton} onPress={pickDocument}>
                    <Text style={styles.changeFileText}>Change file</Text>
                  </TouchableOpacity>
                </View>
              ) : (
                <>
                  <Ionicons 
                    name="document-attach-outline" 
                    size={40} 
                    color="#666666" 
                  />
                  <Text style={styles.uploadText}>Select file or document</Text>
                  <Text style={styles.uploadSubtext}>Supports PDF, DOC, JPG, PNG</Text>
                </>
              )}
            </View>
          </TouchableOpacity>

          {/* <Text style={styles.orText}>or</Text>

          <TouchableOpacity 
            style={styles.cameraButton} 
            onPress={takePhoto}
            activeOpacity={0.8}
          >
            <Ionicons name="camera" size={20} color="#ffffff" />
            <Text style={styles.cameraButtonText}>Open Camera & Take Photo</Text>
          </TouchableOpacity> */}
        </View>

        {/* File Details */}
        {selectedFile && (
          <>
            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Description (Optional)</Text>
              <TextInput
                style={styles.textInput}
                value={description}
                onChangeText={setDescription}
                placeholder="Add a description for your file"
                placeholderTextColor="#666666"
                multiline
                numberOfLines={3}
                textAlignVertical="top"
              />
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Tags (Optional)</Text>
              <TextInput
                style={styles.textInput}
                value={tags}
                onChangeText={setTags}
                placeholder="Enter tags separated by commas (e.g., work, important, pdf)"
                placeholderTextColor="#666666"
              />
              <Text style={styles.helperText}>
                Separate multiple tags with commas
              </Text>
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>Visibility</Text>
              <View style={styles.visibilityOptions}>
                <TouchableOpacity 
                  style={[styles.visibilityOption, isPublic && styles.visibilityOptionActive]}
                  onPress={() => setIsPublic(true)}
                >
                  <Ionicons 
                    name="globe-outline" 
                    size={20} 
                    color={isPublic ? "#00D4AA" : "#666666"} 
                  />
                  <Text style={[styles.visibilityText, isPublic && styles.visibilityTextActive]}>
                    Public
                  </Text>
                </TouchableOpacity>
                
                <TouchableOpacity 
                  style={[styles.visibilityOption, !isPublic && styles.visibilityOptionActive]}
                  onPress={() => setIsPublic(false)}
                >
                  <Ionicons 
                    name="lock-closed-outline" 
                    size={20} 
                    color={!isPublic ? "#00D4AA" : "#666666"} 
                  />
                  <Text style={[styles.visibilityText, !isPublic && styles.visibilityTextActive]}>
                    Private
                  </Text>
                </TouchableOpacity>
              </View>
            </View>

            {/* Upload Progress */}
            {uploading && (
              <View style={styles.progressSection}>
                <Text style={styles.progressText}>Uploading... {uploadProgress}%</Text>
                <View style={styles.progressBar}>
                  <View style={[styles.progressFill, { width: `${uploadProgress}%` }]} />
                </View>
              </View>
            )}
          </>
        )}

         <View style={styles.buttonContainer}>
        <TouchableOpacity 
          style={[
            styles.uploadButton, 
            (!selectedFile || uploading) ? styles.uploadButtonDisabled : styles.uploadButtonActive
          ]} 
          onPress={handleUpload}
          disabled={!selectedFile || uploading}
          activeOpacity={0.8}
        >
          {uploading ? (
            <ActivityIndicator color="#ffffff" size="small" />
          ) : (
            <Ionicons name="cloud-upload" size={20} color="#ffffff" />
          )}
          <Text style={styles.uploadButtonText}>
            {uploading ? 'Uploading...' : 'Upload & Share'}
          </Text>
        </TouchableOpacity>
      </View> 
        
      </ScrollView>

      {/* Upload Button - Fixed at bottom */}
      {/* <View style={styles.buttonContainer}>
        <TouchableOpacity 
          style={[
            styles.uploadButton, 
            (!selectedFile || uploading) ? styles.uploadButtonDisabled : styles.uploadButtonActive
          ]} 
          onPress={handleUpload}
          disabled={!selectedFile || uploading}
          activeOpacity={0.8}
        >
          {uploading ? (
            <ActivityIndicator color="#ffffff" size="small" />
          ) : (
            <Ionicons name="cloud-upload" size={20} color="#ffffff" />
          )}
          <Text style={styles.uploadButtonText}>
            {uploading ? 'Uploading...' : 'Upload & Share'}
          </Text>
        </TouchableOpacity>
      </View> */}
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
    paddingTop: 40,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#ffffff',
    lineHeight: 30,
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  subtitle: {
    fontSize: 14,
    color: '#888888',
    lineHeight: 20,
    marginBottom: 32,
  },
  section: {
    marginBottom: 24,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#ffffff',
    marginBottom: 12,
  },
  uploadContainer: {
    marginBottom: 16,
  },
  uploadBox: {
    borderWidth: 2,
    borderColor: '#00D4AA',
    borderStyle: 'dashed',
    borderRadius: 12,
    paddingVertical: 40,
    paddingHorizontal: 20,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#242424',
  },
  uploadText: {
    color: '#666666',
    fontSize: 16,
    marginTop: 12,
    fontWeight: '500',
  },
  uploadSubtext: {
    color: '#555555',
    fontSize: 12,
    marginTop: 4,
  },
  selectedFileContainer: {
    alignItems: 'center',
  },
  selectedFileText: {
    color: '#00D4AA',
    fontSize: 16,
    fontWeight: '500',
    marginTop: 12,
    textAlign: 'center',
  },
  selectedFileSubtext: {
    color: '#888888',
    fontSize: 12,
    marginTop: 4,
  },
  changeFileButton: {
    marginTop: 12,
    paddingHorizontal: 16,
    paddingVertical: 6,
    backgroundColor: '#333333',
    borderRadius: 16,
  },
  changeFileText: {
    color: '#00D4AA',
    fontSize: 12,
    fontWeight: '500',
  },
  orText: {
    color: '#666666',
    fontSize: 14,
    textAlign: 'center',
    marginBottom: 16,
  },
  cameraButton: {
    backgroundColor: '#333333',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 16,
    borderRadius: 12,
  },
  cameraButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '500',
    marginLeft: 8,
  },
  textInput: {
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 12,
    fontSize: 16,
    color: '#ffffff',
    borderWidth: 1,
    borderColor: '#3a3a3a',
    minHeight: 48,
  },
  helperText: {
    fontSize: 12,
    color: '#666666',
    marginTop: 6,
  },
  visibilityOptions: {
    flexDirection: 'row',
    gap: 12,
  },
  visibilityOption: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    paddingVertical: 16,
    paddingHorizontal: 20,
    borderWidth: 1,
    borderColor: '#3a3a3a',
  },
  visibilityOptionActive: {
    borderColor: '#00D4AA',
    backgroundColor: '#1a2a2a',
  },
  visibilityText: {
    fontSize: 16,
    color: '#666666',
    marginLeft: 8,
    fontWeight: '500',
  },
  visibilityTextActive: {
    color: '#00D4AA',
  },
  progressSection: {
    marginTop: 16,
  },
  progressText: {
    fontSize: 14,
    color: '#00D4AA',
    marginBottom: 8,
    textAlign: 'center',
  },
  progressBar: {
    height: 4,
    backgroundColor: '#3a3a3a',
    borderRadius: 2,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#00D4AA',
    borderRadius: 2,
  },
  buttonContainer: {
    paddingBottom:50,
    backgroundColor: '#1a1a1a',
  },
  uploadButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 16,
    borderRadius: 12,
  },
  uploadButtonActive: {
    backgroundColor: '#00D4AA',
  },
  uploadButtonDisabled: {
    backgroundColor: '#333333',
  },
  uploadButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: 'bold',
    marginLeft: 8,
  },
});

export default SendScreen;