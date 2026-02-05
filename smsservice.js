/**
 * SMS Service - Integration with MO SMS Composer
 * Mock implementation for demo with audit logging
 */

class SMSService {
  constructor() {
    this.deliveryQueue = new Map();
    this.deliveryCounter = 0;
  }

  async send({ to, message, sessionId, username }) {
    // Validate phone format
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    if (!phoneRegex.test(to)) {
      throw new Error('Invalid phone number format');
    }

    // Simulate SMS Composer API call
    const deliveryId = `MO-${Date.now()}-${++this.deliveryCounter}`;
    
    // Mock delivery record
    const delivery = {
      id: deliveryId,
      to: to.replace(/\d(?=\d{4})/g, '*'), // Mask in logs
      timestamp: new Date().toISOString(),
      status: 'queued',
      sessionId,
      username
    };

    this.deliveryQueue.set(deliveryId, delivery);

    // Simulate async delivery
    setTimeout(() => {
      delivery.status = Math.random() > 0.1 ? 'delivered' : 'failed';
      delivery.deliveredAt = new Date().toISOString();
    }, 1000);

    return { id: deliveryId, status: 'queued' };
  }

  async getStatus(deliveryId) {
    const delivery = this.deliveryQueue.get(deliveryId);
    if (!delivery) {
      throw new Error('Delivery not found');
    }
    return {
      id: delivery.id,
      status: delivery.status,
      timestamp: delivery.timestamp,
      deliveredAt: delivery.deliveredAt
    };
  }

  // For demo: Get queue stats
  getStats() {
    const all = Array.from(this.deliveryQueue.values());
    return {
      total: all.length,
      queued: all.filter(d => d.status === 'queued').length,
      delivered: all.filter(d => d.status === 'delivered').length,
      failed: all.filter(d => d.status === 'failed').length
    };
  }
}

module.exports = new SMSService();
