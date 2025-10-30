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
  Modal,
  TextInput,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { router } from 'expo-router';
import { SafeAreaView } from "react-native-safe-area-context";
import * as SecureStore from 'expo-secure-store';
import config from '../../config';

interface Requester {
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
  requester: Requester;
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

const RequestReceivedScreen = () => {
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [responding, setResponding] = useState<string | null>(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<AccessRequest | null>(null);
  const [durationHours, setDurationHours] = useState('24');
  const [responseMessage, setResponseMessage] = useState('');

  useEffect(() => {
    const initScreen = async () => {
      try {
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

      const response = await fetch(`${config.BASE_URL}/api/access-requests/received/${uid}`, {
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

  const handleApproveRequest = (request: AccessRequest) => {
    setSelectedRequest(request);
    setDurationHours('24');
    setResponseMessage('');
    setModalVisible(true);
  };

  const handleRejectRequest = (request: AccessRequest) => {
    Alert.alert(
      "Reject Request",
      `Are you sure you want to reject ${request.requester.username}'s request?`,
      [
        { text: "Cancel", onPress: () => {} },
        {
          text: "Reject",
          onPress: () => respondToRequest(request.id, 'reject', '', 0),
          style: "destructive",
        },
      ]
    );
  };

  const respondToRequest = async (requestId: string, action: 'approve' | 'reject', message: string, duration: number) => {
    try {
      setResponding(requestId);
      setModalVisible(false);

      const token = await SecureStore.getItemAsync("authToken");
      if (!token) {
        Alert.alert("Error", "Authentication token not found");
        return;
      }

      const payload = {
        requestId,
        ownerId: userId,
        action,
        responseMessage: message,
        ...(action === 'approve' && { durationHours: duration })
      };

      const response = await fetch(
        `${config.BASE_URL}/api/access-requests/respond`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      console.log("✅ Request responded:", data);

      // Update request in list
      setRequests((prev) =>
        prev.map((req) =>
          req.id === requestId
            ? {
                ...req,
                status: action === 'approve' ? 'approved' : 'rejected',
                responseTime: new Date().toISOString(),
                responseMessage: message,
              }
            : req
        )
      );

      // Update stats
      if (stats) {
        const updatedRequest = requests.find(r => r.id === requestId);
        if (updatedRequest && updatedRequest.status === 'pending') {
          setStats({
            ...stats,
            pending: stats.pending - 1,
            [action === 'approve' ? 'approved' : 'rejected']: stats[action === 'approve' ? 'approved' : 'rejected'] + 1,
          });
        }
      }

      Alert.alert("Success", `Request ${action === 'approve' ? 'approved' : 'rejected'} successfully`);
    } catch (err) {
      console.error("Error responding to request:", err);
      Alert.alert("Error", err instanceof Error ? err.message : "Failed to respond to request");
    } finally {
      setResponding(null);
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
      {/* Header with requester info */}
      <View style={styles.cardHeader}>
        <View style={styles.requesterInfo}>
          <View style={styles.requesterAvatar}>
            <Text style={styles.avatarText}>
              {item.requester.username.charAt(0).toUpperCase()}
            </Text>
          </View>
          <View style={styles.requesterDetails}>
            <Text style={styles.requesterName}>{item.requester.username}</Text>
            <Text style={styles.requesterEmail} numberOfLines={1}>
              {item.requester.email}
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

      {/* Action buttons - only for pending requests */}
      {item.status === 'pending' && (
        <View style={styles.actionButtons}>
          <TouchableOpacity
            style={[styles.actionButton, styles.rejectButton]}
            onPress={() => handleRejectRequest(item)}
            disabled={responding === item.id}
          >
            {responding === item.id ? (
              <ActivityIndicator size="small" color="#FF6B6B" />
            ) : (
              <>
                <Ionicons name="close-circle" size={18} color="#FF6B6B" />
                <Text style={styles.rejectButtonText}>Reject</Text>
              </>
            )}
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.actionButton, styles.approveButton]}
            onPress={() => handleApproveRequest(item)}
            disabled={responding === item.id}
          >
            {responding === item.id ? (
              <ActivityIndicator size="small" color="#2ECC71" />
            ) : (
              <>
                <Ionicons name="checkmark-circle" size={18} color="#2ECC71" />
                <Text style={styles.approveButtonText}>Approve</Text>
              </>
            )}
          </TouchableOpacity>
        </View>
      )}
    </View>
  );

  const renderEmptyState = () => (
    <View style={styles.emptyContainer}>
      <Ionicons name="download" size={64} color="#444444" />
      <Text style={styles.emptyTitle}>No Requests Received</Text>
      <Text style={styles.emptyMessage}>
        You haven't received any access requests yet
      </Text>
    </View>
  );

  const handleApproveConfirm = () => {
    if (!selectedRequest) return;
    const duration = parseInt(durationHours) || 24;
    respondToRequest(selectedRequest.id, 'approve', responseMessage, duration);
  };

  return (
    <SafeAreaView style={styles.container} edges={['top']}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={handleBack}>
          <Ionicons name="arrow-back" size={24} color="#ffffff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Received Requests</Text>
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

      {/* Approve Modal */}
      <Modal
        visible={modalVisible}
        transparent={true}
        animationType="slide"
        onRequestClose={() => setModalVisible(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>Approve Access Request</Text>
              <TouchableOpacity onPress={() => setModalVisible(false)}>
                <Ionicons name="close" size={24} color="#ffffff" />
              </TouchableOpacity>
            </View>

            <ScrollView style={styles.modalBody}>
              {selectedRequest && (
                <>
                  {/* Request Summary */}
                  <View style={styles.summaryContainer}>
                    <Text style={styles.summaryLabel}>Requester:</Text>
                    <Text style={styles.summaryValue}>{selectedRequest.requester.username}</Text>

                    <Text style={[styles.summaryLabel, { marginTop: 12 }]}>File:</Text>
                    <Text style={styles.summaryValue}>{selectedRequest.file.name}</Text>

                    <Text style={[styles.summaryLabel, { marginTop: 12 }]}>Purpose:</Text>
                    <Text style={styles.summaryValue}>{selectedRequest.purpose}</Text>
                  </View>

                  {/* Duration Input */}
                  <View style={styles.inputContainer}>
                    <Text style={styles.inputLabel}>Duration (hours)</Text>
                    <TextInput
                      style={styles.textInput}
                      placeholder="24"
                      placeholderTextColor="#666666"
                      keyboardType="number-pad"
                      value={durationHours}
                      onChangeText={setDurationHours}
                    />
                    <Text style={styles.inputHint}>Default: 24 hours</Text>
                  </View>

                  {/* Response Message Input */}
                  <View style={styles.inputContainer}>
                    <Text style={styles.inputLabel}>Response Message (Optional)</Text>
                    <TextInput
                      style={[styles.textInput, styles.multilineInput]}
                      placeholder="Add a message..."
                      placeholderTextColor="#666666"
                      multiline={true}
                      numberOfLines={3}
                      value={responseMessage}
                      onChangeText={setResponseMessage}
                    />
                  </View>
                </>
              )}
            </ScrollView>

            {/* Modal Buttons */}
            <View style={styles.modalButtons}>
              <TouchableOpacity
                style={styles.modalCancelButton}
                onPress={() => setModalVisible(false)}
              >
                <Text style={styles.modalCancelButtonText}>Cancel</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={styles.modalApproveButton}
                onPress={handleApproveConfirm}
              >
                <Text style={styles.modalApproveButtonText}>Approve</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
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
    marginHorizontal: 20,
    marginTop:10,
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
  requesterInfo: { flexDirection: 'row', alignItems: 'center', flex: 1 },
  requesterAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#00D4AA',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  avatarText: { fontSize: 16, fontWeight: 'bold', color: '#1a1a1a' },
  requesterDetails: { flex: 1 },
  requesterName: { fontSize: 14, fontWeight: '600', color: '#ffffff', marginBottom: 2 },
  requesterEmail: { fontSize: 12, color: '#888888' },
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
  actionButtons: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 12,
  },
  actionButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 12,
    borderRadius: 8,
    gap: 6,
  },
  rejectButton: {
    backgroundColor: '#3a2a2a',
    borderWidth: 1,
    borderColor: '#FF6B6B',
  },
  rejectButtonText: { fontSize: 14, color: '#FF6B6B', fontWeight: '600' },
  approveButton: {
    backgroundColor: '#2a3a2a',
    borderWidth: 1,
    borderColor: '#2ECC71',
  },
  approveButtonText: { fontSize: 14, color: '#2ECC71', fontWeight: '600' },
  emptyContainer: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 20 },
  emptyTitle: { fontSize: 18, fontWeight: '600', color: '#ffffff', marginTop: 16, marginBottom: 8 },
  emptyMessage: { fontSize: 14, color: '#888888', textAlign: 'center' },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    justifyContent: 'flex-end',
  },
  modalContent: {
    backgroundColor: '#2a2a2a',
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    paddingTop: 20,
    maxHeight: '80%',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingBottom: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#3a3a3a',
  },
  modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#ffffff' },
  modalBody: { paddingHorizontal: 20, paddingVertical: 16 },
  summaryContainer: { marginBottom: 20 },
  summaryLabel: { fontSize: 12, color: '#888888', marginBottom: 4 },
  summaryValue: { fontSize: 14, color: '#ffffff', fontWeight: '500' },
  inputContainer: { marginBottom: 16 },
  inputLabel: { fontSize: 14, fontWeight: '600', color: '#ffffff', marginBottom: 8 },
  textInput: {
    backgroundColor: '#1a1a1a',
    borderWidth: 1,
    borderColor: '#3a3a3a',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: '#ffffff',
    fontSize: 14,
  },
  multilineInput: { minHeight: 80, textAlignVertical: 'top' },
  inputHint: { fontSize: 12, color: '#666666', marginTop: 4 },
  modalButtons: {
    flexDirection: 'row',
    gap: 12,
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderTopWidth: 1,
    borderTopColor: '#3a3a3a',
  },
  modalCancelButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 8,
    backgroundColor: '#3a3a3a',
    alignItems: 'center',
  },
  modalCancelButtonText: { fontSize: 14, color: '#ffffff', fontWeight: '600' },
  modalApproveButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 8,
    backgroundColor: '#2ECC71',
    alignItems: 'center',
  },
  modalApproveButtonText: { fontSize: 14, color: '#1a1a1a', fontWeight: '600' },
});

export default RequestReceivedScreen;