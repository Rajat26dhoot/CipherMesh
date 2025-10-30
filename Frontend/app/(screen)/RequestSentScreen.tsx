import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  Alert,
  FlatList,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { router } from 'expo-router';
import { SafeAreaView } from "react-native-safe-area-context";
import * as SecureStore from 'expo-secure-store';
import config from '../../config';

interface Owner {
  id: string;
  username: string;
  email: string;
  blockchainAddress: string;
}

interface File {
  id: string;
  name: string;
  description: string;
  size: number;
  sizeFormatted: string;
  mimetype: string;
}

interface AccessRequest {
  id: string;
  owner: Owner;
  file: File;
  purpose: string;
  requestedDuration: string;
  requestTime: string;
  status: 'pending' | 'approved' | 'rejected';
  responseTime?: string;
  responseMessage?: string;
}

interface Stats {
  total: number;
  pending: number;
  approved: number;
  rejected: number;
}

const RequestSentScreen = () => {
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  useEffect(() => {
    const initScreen = async () => {
      try {
        // Get userId from secure store or user data
        const token = await SecureStore.getItemAsync("authToken");
        const userIdStored = await SecureStore.getItemAsync("userId");
        
        if (userIdStored) {
          setUserId(userIdStored);
          await fetchRequests(userIdStored);
        } else {
          setError("User ID not found");
        }
      } catch (err) {
        console.error("Initialization error:", err);
        setError("Failed to initialize");
      }
    };

    initScreen();
  }, []);

  const fetchRequests = async (uid: string) => {
    try {
      setLoading(true);
      setError(null);

      const token = await SecureStore.getItemAsync("authToken");
      if (!token) {
        setError("No authentication token found");
        router.replace("/(auth)/welcome");
        return;
      }

      const response = await fetch(`${config.BASE_URL}/api/access-requests/sent/${uid}`, {
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
      console.log("✅ Requests fetched:", data);

      if (!data.success) {
        throw new Error(data.error || "Failed to load requests");
      }

      setRequests(data.requests || []);
      setStats(data.stats);
    } catch (err) {
      console.error("Error fetching requests:", err);
      setError(err instanceof Error ? err.message : "Failed to fetch requests");
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteRequest = (requestId: string) => {
    Alert.alert(
      "Cancel Request",
      "Are you sure you want to cancel this access request?",
      [
        { text: "No", onPress: () => {} },
        {
          text: "Yes",
          onPress: () => deleteRequest(requestId),
          style: "destructive",
        },
      ]
    );
  };

  const deleteRequest = async (requestId: string) => {
    try {
      setDeleting(requestId);

      const token = await SecureStore.getItemAsync("authToken");
      if (!token) {
        Alert.alert("Error", "Authentication token not found");
        return;
      }

      const response = await fetch(
        `${config.BASE_URL}/api/access-requests/${requestId}?userId=${userId}`,
        {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      console.log("✅ Request deleted:", data);

      // Remove from list
      setRequests((prev) => prev.filter((req) => req.id !== requestId));

      // Update stats
      if (stats) {
        setStats({
          ...stats,
          total: stats.total - 1,
          pending: stats.pending - (requests.find(r => r.id === requestId)?.status === 'pending' ? 1 : 0),
        });
      }

      Alert.alert("Success", "Access request cancelled successfully");
    } catch (err) {
      console.error("Error deleting request:", err);
      Alert.alert("Error", err instanceof Error ? err.message : "Failed to delete request");
    } finally {
      setDeleting(null);
    }
  };

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'pending':
        return '#FFD700';
      case 'approved':
        return '#2ECC71';
      case 'rejected':
        return '#FF6B6B';
      default:
        return '#888888';
    }
  };

  const handleBack = () => router.back();

  const renderRequestCard = ({ item }: { item: AccessRequest }) => (
    <View style={styles.requestCard}>
      {/* Header with owner info */}
      <View style={styles.cardHeader}>
        <View style={styles.ownerInfo}>
          <View style={styles.ownerAvatar}>
            <Text style={styles.avatarText}>
              {item.owner.username.charAt(0).toUpperCase()}
            </Text>
          </View>
          <View style={styles.ownerDetails}>
            <Text style={styles.ownerName}>{item.owner.username}</Text>
            <Text style={styles.ownerEmail} numberOfLines={1}>
              {item.owner.email}
            </Text>
          </View>
        </View>
        <View style={[styles.statusBadge, { backgroundColor: getStatusColor(item.status) }]}>
          <Text style={styles.statusText}>{item.status.charAt(0).toUpperCase() + item.status.slice(1)}</Text>
        </View>
      </View>

      {/* File info */}
      <View style={styles.fileInfo}>
        <View style={styles.fileIcon}>
          <Ionicons name="document" size={20} color="#00D4AA" />
        </View>
        <View style={styles.fileDetails}>
          <Text style={styles.fileName} numberOfLines={1}>
            {item.file.name}
          </Text>
          <Text style={styles.fileSize}>
            {item.file.sizeFormatted} • {item.file.mimetype}
          </Text>
        </View>
      </View>

      {/* Purpose and duration */}
      <View style={styles.detailsContainer}>
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Purpose:</Text>
          <Text style={styles.detailValue}>{item.purpose}</Text>
        </View>
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Duration:</Text>
          <Text style={styles.detailValue}>{item.requestedDuration}</Text>
        </View>
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Requested:</Text>
          <Text style={styles.detailValue}>{formatDate(item.requestTime)}</Text>
        </View>

        {item.status !== 'pending' && item.responseTime && (
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Responded:</Text>
            <Text style={styles.detailValue}>{formatDate(item.responseTime)}</Text>
          </View>
        )}

        {item.responseMessage && (
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Message:</Text>
            <Text style={styles.detailValue}>{item.responseMessage}</Text>
          </View>
        )}
      </View>

      {/* Delete button - only for pending requests */}
      {item.status === 'pending' && (
        <TouchableOpacity
          style={styles.deleteButton}
          onPress={() => handleDeleteRequest(item.id)}
          disabled={deleting === item.id}
        >
          {deleting === item.id ? (
            <ActivityIndicator size="small" color="#FF6B6B" />
          ) : (
            <>
              <Ionicons name="trash" size={18} color="#FF6B6B" />
              <Text style={styles.deleteButtonText}>Cancel Request</Text>
            </>
          )}
        </TouchableOpacity>
      )}
    </View>
  );

  const renderEmptyState = () => (
    <View style={styles.emptyContainer}>
      <Ionicons name="send" size={64} color="#444444" />
      <Text style={styles.emptyTitle}>No Requests Sent</Text>
      <Text style={styles.emptyMessage}>
        You haven't sent any access requests yet
      </Text>
    </View>
  );

  return (
    <SafeAreaView style={styles.container} edges={['top']}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={handleBack}>
          <Ionicons name="arrow-back" size={24} color="#ffffff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Sent Requests</Text>
      </View>

      {loading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#00D4AA" />
          <Text style={styles.loadingText}>Loading requests...</Text>
        </View>
      ) : error ? (
        <View style={styles.errorContainer}>
          <Ionicons name="alert-circle" size={48} color="#FF6B6B" />
          <Text style={styles.errorText}>{error}</Text>
          <TouchableOpacity
            style={styles.retryButton}
            onPress={() => userId && fetchRequests(userId)}
          >
            <Text style={styles.retryButtonText}>Retry</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <>
          {/* Stats */}
          {stats && (
            <View style={styles.statsContainer}>
              <View style={styles.statItem}>
                <Text style={styles.statValue}>{stats.total}</Text>
                <Text style={styles.statLabel}>Total</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={[styles.statValue, { color: '#FFD700' }]}>
                  {stats.pending}
                </Text>
                <Text style={styles.statLabel}>Pending</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={[styles.statValue, { color: '#2ECC71' }]}>
                  {stats.approved}
                </Text>
                <Text style={styles.statLabel}>Approved</Text>
              </View>
              <View style={styles.statItem}>
                <Text style={[styles.statValue, { color: '#FF6B6B' }]}>
                  {stats.rejected}
                </Text>
                <Text style={styles.statLabel}>Rejected</Text>
              </View>
            </View>
          )}

          {/* Requests List */}
          <FlatList
            data={requests}
            renderItem={renderRequestCard}
            keyExtractor={(item) => item.id}
            contentContainerStyle={styles.listContainer}
            ListEmptyComponent={renderEmptyState}
            scrollEnabled={true}
          />
        </>
      )}
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
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#2a2a2a',
    alignItems: 'center',
    justifyContent: 'center',
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#ffffff',
    marginLeft: 16,
    flex: 1,
  },
  loadingContainer: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  loadingText: { color: '#888888', fontSize: 16, marginTop: 12 },
  errorContainer: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 },
  errorText: { color: '#FF6B6B', fontSize: 16, textAlign: 'center', marginTop: 12, marginBottom: 20 },
  retryButton: { backgroundColor: '#00D4AA', paddingHorizontal: 20, paddingVertical: 10, borderRadius: 8 },
  retryButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '600' },
  statsContainer: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    paddingVertical: 16,
    backgroundColor: '#2a2a2a',
    marginBottom: 16,
    marginTop:10,
    marginHorizontal: 20,
    borderRadius: 12,
  },
  statItem: { flex: 1, alignItems: 'center' },
  statValue: { fontSize: 20, fontWeight: 'bold', color: '#00D4AA', marginBottom: 4 },
  statLabel: { fontSize: 12, color: '#888888' },
  listContainer: { paddingHorizontal: 20, paddingVertical: 12 },
  requestCard: {
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    borderLeftWidth: 4,
    borderLeftColor: '#00D4AA',
  },
  cardHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 },
  ownerInfo: { flexDirection: 'row', alignItems: 'center', flex: 1 },
  ownerAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#00D4AA',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  avatarText: { fontSize: 16, fontWeight: 'bold', color: '#1a1a1a' },
  ownerDetails: { flex: 1 },
  ownerName: { fontSize: 14, fontWeight: '600', color: '#ffffff', marginBottom: 2 },
  ownerEmail: { fontSize: 12, color: '#888888' },
  statusBadge: {
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 6,
    marginLeft: 8,
  },
  statusText: { fontSize: 11, fontWeight: '600', color: '#1a1a1a' },
  fileInfo: { flexDirection: 'row', alignItems: 'center', paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: '#3a3a3a' },
  fileIcon: { marginRight: 12 },
  fileDetails: { flex: 1 },
  fileName: { fontSize: 14, fontWeight: '500', color: '#ffffff', marginBottom: 2 },
  fileSize: { fontSize: 12, color: '#888888' },
  detailsContainer: { paddingVertical: 12 },
  detailRow: { marginBottom: 8 },
  detailLabel: { fontSize: 12, color: '#888888', marginBottom: 2 },
  detailValue: { fontSize: 13, color: '#dddddd' },
  deleteButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#3a2a2a',
    paddingVertical: 12,
    borderRadius: 8,
    marginTop: 12,
    gap: 8,
  },
  deleteButtonText: { fontSize: 14, color: '#FF6B6B', fontWeight: '600' },
  emptyContainer: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 },
  emptyTitle: { fontSize: 18, fontWeight: '600', color: '#ffffff', marginTop: 16, marginBottom: 8 },
  emptyMessage: { fontSize: 14, color: '#888888', textAlign: 'center' },
});

export default RequestSentScreen;