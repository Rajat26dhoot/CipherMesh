import React, { useEffect, useState } from 'react';
import { 
  View, 
  Text, 
  StyleSheet, 
  ScrollView, 
  TouchableOpacity, 
  ActivityIndicator, 
  Alert 
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as SecureStore from 'expo-secure-store';
import { router } from 'expo-router';
import config from '../../config'; 
interface FileItem {
  id: string;
  originalName: string;
  description: string;
  sizeFormatted: string;
  mimetype: string;
  uploadTime: string;
  owner: {
    username: string;
    email: string;
  };
  permissions: {
    activeShares: number;
  };
}

const ReceiveScreen = () => {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchFiles = async () => {
    setLoading(true);
    try {
      const authToken = await SecureStore.getItemAsync('authToken'); // optional if API requires auth
      const response = await fetch(`${config.BASE_URL}/api/files`, {
        method: 'GET',
        headers: {
          'Authorization': authToken ? `Bearer ${authToken}` : '',
        },
      });
      const data = await response.json();

      if (!response.ok || data.success === false) {
        throw new Error(data?.error || 'Failed to fetch files');
      }

      setFiles(data.files || []);
    } catch (error: any) {
      console.error('Fetch files error:', error.message);
      Alert.alert('Error', error.message || 'Unable to fetch files');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleFilePress = (fileId: string) => {
    router.push({
      pathname: '/(screen)/file-details',
      params: { fileKey: fileId },
    });
  };

  return (
    <SafeAreaView style={styles.container}  edges={['top']}>
      <Text style={styles.title}>Available Files</Text>

      {loading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#00D4AA" />
          <Text style={styles.loadingText}>Loading files...</Text>
        </View>
      ) : files.length === 0 ? (
        <View style={styles.emptyContainer}>
          <Text style={styles.emptyText}>No files available.</Text>
        </View>
      ) : (
        <ScrollView style={styles.scrollContainer}>
          {files.map((file) => (
            <TouchableOpacity
              key={file.id}
              style={styles.fileCard}
              onPress={() => handleFilePress(file.id)}
            >
              <View style={styles.fileHeader}>
                <Ionicons name="document-text-outline" size={28} color="#00D4AA" />
                <Text style={styles.fileName}>{file.originalName}</Text>
              </View>
              <Text style={styles.fileDescription}>{file.description || 'No description'}</Text>
              <View style={styles.fileMeta}>
                <Text style={styles.metaText}>Size: {file.sizeFormatted}</Text>
                <Text style={styles.metaText}>Owner: {file.owner.username}</Text>
              </View>
            </TouchableOpacity>
          ))}
        </ScrollView>
      )}
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a1a',
    paddingHorizontal: 16,
    paddingTop: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#ffffff',
    marginBottom: 20,
  },
  scrollContainer: {
    flex: 1,
  },
  fileCard: {
    backgroundColor: '#242424',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: '#333333',
  },
  fileHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
    gap: 10,
  },
  fileName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#00D4AA',
  },
  fileDescription: {
    fontSize: 14,
    color: '#888888',
    marginBottom: 8,
  },
  fileMeta: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  metaText: {
    fontSize: 12,
    color: '#666666',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: '#00D4AA',
    marginTop: 8,
    fontSize: 14,
  },
  emptyContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  emptyText: {
    color: '#666666',
    fontSize: 14,
  },
});

export default ReceiveScreen;
