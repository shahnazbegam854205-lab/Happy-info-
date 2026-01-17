// /api/search.js - COMPLETE WITH ADMIN KEY SYSTEM
import { initializeApp, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getDatabase } from 'firebase-admin/database';
import crypto from 'crypto';

// Initialize Firebase Admin
const firebaseAdmin = initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL
}, 'backend');

const adminAuth = getAuth(firebaseAdmin);
const adminDb = getDatabase(firebaseAdmin);

// ===================== CONFIG =====================
const CONFIG = {
  PLATFORM_PRICE: 1.5,
  DEVELOPER_PRICE: 1.0,
  DIRECT_USER_PRICE: 1.5,
  COST_PER_SEARCH: 1,
  MIN_PURCHASE: 10,
  MIN_WITHDRAWAL: 100,
  DEFAULT_COMMISSION: 0.5,
  MAX_COMMISSION: 1.0,
  MIN_COMMISSION: 0.1,
  SIGNUP_BONUS_CREDITS: 10,
  SIGNUP_BONUS_ENABLED: true,
  ID_VISIBILITY_THRESHOLD: 500,
  WEBSITE_MODE: {
    ENABLED: true,
    MAX_DOMAINS: 5,
    REQUIRE_HTTPS: true,
    ALLOW_LOCALHOST: true,
    RATE_LIMIT_PER_DOMAIN: 1000
  },
  ADMIN_UPI: process.env.ADMIN_UPI || 'admin@upi',
  
  // ✅ ADMIN KEY CONFIG
  ADMIN_KEY: process.env.ADMIN_KEY || 'default-admin-key-123',
  SUPER_ADMIN_KEY: process.env.SUPER_ADMIN_KEY || 'super-admin-key-456',
  
  RATE_LIMITS: {
    USER: { per_minute: 60, per_hour: 300 },
    DEVELOPER: { per_minute: 200, per_hour: 1000 }
  },
  API_KEY_EXPIRY_DAYS: 90,
  MAX_API_KEYS_PER_USER: 5,
  MAX_RESULTS: 100,
  SEARCH_TIMEOUT: 30000
};

// ===================== HELPER FUNCTIONS =====================
function generateApiKey(uid) {
  return `api_${uid}_${Date.now()}_${crypto.randomBytes(16).toString('hex')}`;
}

function generateReferralCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = 'REF';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

function maskIdNumber(idNumber) {
  if (!idNumber) return null;
  const length = idNumber.length;
  if (length <= 4) return idNumber;
  return 'X'.repeat(length - 4) + idNumber.slice(-4);
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.connection.remoteAddress || 
         'unknown';
}

function extractDomain(url) {
  if (!url) return null;
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function normalizeDomain(domain) {
  if (!domain) return '';
  return domain.toLowerCase().trim()
    .replace(/^(https?:\/\/)?(www\.)?/, '')
    .replace(/\/$/, '');
}

async function logSecurityEvent(userId, action, details) {
  try {
    await adminDb.ref(`security_logs/${Date.now()}_${userId}`).set({
      user_id: userId,
      action,
      details,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Security log error:', error);
  }
}

// ✅ GET ADMIN KEY FROM REQUEST
function getAdminKeyFromRequest(req) {
  return req.headers['x-admin-key'] || 
         req.headers['authorization']?.replace('AdminKey ', '') || 
         req.query.admin_key;
}

// ✅ ADMIN KEY VERIFICATION
async function verifyAdminKey(adminKey) {
  try {
    // Check super admin key
    if (adminKey === CONFIG.SUPER_ADMIN_KEY) {
      return {
        success: true,
        is_super_admin: true,
        permissions: ['all'],
        message: 'Super admin access granted'
      };
    }
    
    // Check regular admin key
    if (adminKey === CONFIG.ADMIN_KEY) {
      return {
        success: true,
        is_super_admin: false,
        permissions: ['withdrawal', 'payment', 'users', 'stats', 'developer'],
        message: 'Admin access granted'
      };
    }
    
    return {
      success: false,
      error: 'INVALID_ADMIN_KEY',
      message: 'Invalid admin key'
    };
    
  } catch (error) {
    console.error('Admin key verification error:', error);
    return {
      success: false,
      error: 'ADMIN_KEY_VERIFICATION_FAILED'
    };
  }
}

// ✅ CHECK REFERRAL FUNCTION (DEFINED HERE)
async function handleCheckReferral(req, res) {
  const { referral_code } = req.query;
  
  if (!referral_code) {
    return res.status(400).json({ error: 'REFERRAL_CODE_REQUIRED' });
  }
  
  try {
    const referrerSnap = await adminDb.ref('users')
      .orderByChild('referral_code')
      .equalTo(referral_code.toUpperCase())
      .once('value');
    
    if (!referrerSnap.exists()) {
      return res.status(404).json({ error: 'INVALID_REFERRAL_CODE' });
    }
    
    const referrerId = Object.keys(referrerSnap.val())[0];
    const referrer = referrerSnap.val()[referrerId];
    
    return res.json({
      success: true,
      referrer: {
        name: referrer.name,
        commission: referrer.commission_amount || CONFIG.DEFAULT_COMMISSION
      }
    });
    
  } catch (error) {
    console.error('Referral check error:', error);
    return res.status(500).json({ error: 'REFERRAL_CHECK_FAILED' });
  }
}

async function checkWebsiteAccess(userId, userData, req) {
  const clientIP = getClientIP(req);
  const origin = req.headers.origin || req.headers.referer;
  
  // Non-developers have no restrictions
  if (userData.user_type !== 'developer') {
    return { allowed: true, mode: 'regular_user' };
  }
  
  // Website mode disabled - use IP whitelist
  if (!userData.website_mode) {
    const whitelist = userData.ip_whitelist || [];
    if (whitelist.length === 0 || whitelist.includes(clientIP)) {
      return { allowed: true, mode: 'ip_whitelist' };
    }
    return {
      allowed: false,
      error: 'IP_NOT_WHITELISTED',
      message: 'Your IP is not authorized',
      details: { your_ip: clientIP }
    };
  }
  
  // Website mode enabled - check domains
  const allowedDomains = userData.domains || [];
  if (allowedDomains.length === 0) {
    return { allowed: true, mode: 'website_no_domains' };
  }
  
  const requestDomain = extractDomain(origin);
  if (!requestDomain) {
    // Direct API call
    if (userData.allow_direct_calls !== false) {
      return { allowed: true, mode: 'direct_call' };
    }
    return {
      allowed: false,
      error: 'DIRECT_CALLS_DISABLED'
    };
  }
  
  // Check domain
  for (const domain of allowedDomains) {
    if (requestDomain === domain || requestDomain.endsWith(`.${domain}`)) {
      return { allowed: true, mode: 'website_domain', domain: requestDomain };
    }
  }
  
  return {
    allowed: false,
    error: 'DOMAIN_NOT_ALLOWED',
    message: 'Your domain is not authorized',
    details: { your_domain: requestDomain, allowed_domains: allowedDomains }
  };
}

async function verifyUser(token) {
  try {
    const decoded = await adminAuth.verifyIdToken(token);
    const userRecord = await adminAuth.getUser(decoded.uid);
    
    if (!userRecord.emailVerified) {
      return { success: false, error: 'EMAIL_NOT_VERIFIED' };
    }
    
    const userRef = adminDb.ref(`users/${decoded.uid}`);
    const userSnap = await userRef.once('value');
    const userData = userSnap.val();
    
    if (!userData) {
      return { success: false, error: 'USER_NOT_FOUND' };
    }
    
    return { success: true, uid: decoded.uid, userData };
  } catch (error) {
    return { success: false, error: 'AUTH_FAILED', message: error.message };
  }
}

async function verifyApiKey(apiKey, req) {
  try {
    const userSnap = await adminDb.ref('users')
      .orderByChild('api_key')
      .equalTo(apiKey)
      .once('value');
    
    if (!userSnap.exists()) {
      return { success: false, error: 'INVALID_API_KEY' };
    }
    
    const userKey = Object.keys(userSnap.val())[0];
    const userData = userSnap.val()[userKey];
    
    try {
      await adminAuth.getUser(userKey);
    } catch {
      return { success: false, error: 'USER_NOT_FOUND' };
    }
    
    // Check access
    const accessCheck = await checkWebsiteAccess(userKey, userData, req);
    if (!accessCheck.allowed) {
      return {
        success: false,
        error: accessCheck.error || 'ACCESS_DENIED',
        message: accessCheck.message,
        details: accessCheck.details
      };
    }
    
    return {
      success: true,
      uid: userKey,
      userData,
      access_info: { mode: accessCheck.mode, domain: accessCheck.domain }
    };
  } catch (error) {
    return { success: false, error: 'API_KEY_VERIFICATION_FAILED' };
  }
}

async function calculateUserPrice(userId) {
  const userSnap = await adminDb.ref(`users/${userId}`).once('value');
  const userData = userSnap.val();
  if (!userData) return CONFIG.DIRECT_USER_PRICE;
  
  if (userData.user_type === 'developer') return CONFIG.DEVELOPER_PRICE;
  
  if (userData.referral_chain?.length > 0) {
    let price = CONFIG.DIRECT_USER_PRICE;
    for (const referrerId of userData.referral_chain) {
      const referrerSnap = await adminDb.ref(`users/${referrerId}`).once('value');
      const referrerData = referrerSnap.val();
      if (referrerData?.commission_amount) {
        price += referrerData.commission_amount;
      }
    }
    return price;
  }
  
  return CONFIG.DIRECT_USER_PRICE;
}

async function getReferralChain(userId) {
  const chain = [];
  let currentId = userId;
  const visited = new Set();
  
  while (currentId && !visited.has(currentId)) {
    visited.add(currentId);
    const userSnap = await adminDb.ref(`users/${currentId}`).once('value');
    const userData = userSnap.val();
    if (!userData) break;
    
    chain.push({
      user_id: currentId,
      name: userData.name,
      email: userData.email,
      commission_amount: userData.commission_amount || CONFIG.DEFAULT_COMMISSION,
      level: chain.length + 1
    });
    
    currentId = userData.referred_by;
  }
  
  return chain;
}

async function distributeReferralCommissions(userId, amount, userPrice) {
  try {
    const userSnap = await adminDb.ref(`users/${userId}`).once('value');
    const userData = userSnap.val();
    if (!userData?.referral_chain) return;
    
    const creditsPurchased = amount / userPrice;
    
    for (let i = 0; i < userData.referral_chain.length; i++) {
      const referrerId = userData.referral_chain[i];
      const referrerSnap = await adminDb.ref(`users/${referrerId}`).once('value');
      const referrerData = referrerSnap.val();
      
      if (referrerData) {
        const commission = creditsPurchased * (referrerData.commission_amount || CONFIG.DEFAULT_COMMISSION);
        
        await adminDb.ref(`users/${referrerId}`).update({
          total_earned: (referrerData.total_earned || 0) + commission,
          referral_earnings: i === 0 ? 
            (referrerData.referral_earnings || 0) + commission : 
            referrerData.referral_earnings || 0,
          indirect_earnings: i > 0 ? 
            (referrerData.indirect_earnings || 0) + commission : 
            referrerData.indirect_earnings || 0
        });
        
        await adminDb.ref(`commissions/${Date.now()}_${referrerId}`).set({
          referrer: referrerId,
          referred_user: userId,
          amount: commission,
          level: i + 1,
          type: i === 0 ? 'direct' : 'indirect',
          date: new Date().toISOString()
        });
      }
    }
  } catch (error) {
    console.error('Commission distribution error:', error);
  }
}

// ===================== MAIN API HANDLER =====================
export default async function handler(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Admin-Key');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  const action = req.query.action;
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  // ✅ Check admin key first for admin endpoints
  const adminKey = getAdminKeyFromRequest(req);
  
  // Public endpoints
  if (action === 'payment_info') {
    return res.json({
      success: true,
      upi_id: CONFIG.ADMIN_UPI,
      min_amount: CONFIG.MIN_PURCHASE
    });
  }
  
  if (action === 'check_referral') {
    return await handleCheckReferral(req, res);
  }
  
  if (action === 'system_info') {
    return res.json({
      success: true,
      system: 'Search API System',
      version: '2.0',
      features: ['Referral System', 'Website Support', 'Payment Processing']
    });
  }
  
  // ✅ Admin key endpoints (no user auth required)
  if (action === 'admin_approve_withdrawal_key') {
    return await handleAdminApproveWithdrawalKey(req, res, adminKey);
  }
  
  if (action === 'admin_approve_payment_key') {
    return await handleAdminApprovePaymentKey(req, res, adminKey);
  }
  
  // Authentication
  let authResult = null;
  if (authHeader?.startsWith('Bearer ')) {
    authResult = await verifyUser(authHeader.split('Bearer ')[1]);
  } else if (apiKey) {
    authResult = await verifyApiKey(apiKey, req);
  }
  
  if (action !== 'signup' && (!authResult || !authResult.success)) {
    return res.status(401).json({
      success: false,
      error: authResult?.error || 'AUTH_REQUIRED',
      message: authResult?.message
    });
  }
  
  const { uid, userData } = authResult || {};
  
  // Route actions
  const handlers = {
    signup: handleSignup,
    get_profile: handleGetProfile,
    submit_payment: handleSubmitPayment,
    check_payment: handleCheckPayment,
    use_referral: handleUseReferral,
    set_commission: handleSetCommission,
    rotate_api_key: handleRotateApiKey,
    manage_ip_whitelist: handleManageIPWhitelist,
    api_key_history: handleApiKeyHistory,
    update_bank_details: handleUpdateBankDetails,
    request_withdrawal: handleRequestWithdrawal,
    referral_network: handleReferralNetwork,
    earnings_report: handleEarningsReport,
    withdrawal_history: handleWithdrawalHistory,
    create_developer: handleCreateDeveloper,
    manage_domains: handleManageDomains,
    website_settings: handleWebsiteSettings,
    search: handleSearch,
    bulk_search: handleBulkSearch,
    search_history: handleSearchHistory,
    admin_approve_payment: handleAdminApprovePayment,
    admin_approve_withdrawal: handleAdminApproveWithdrawal,
    admin_adjust_balance: handleAdminAdjustBalance,
    admin_all_users: handleAdminAllUsers,
    admin_pending_requests: handleAdminPendingRequests,
    admin_system_stats: handleAdminSystemStats,
    admin_manage_developer: handleAdminManageDeveloper
  };
  
  if (handlers[action]) {
    return await handlers[action](req, res, uid, userData);
  }
  
  // Default search
  if (req.query.number || req.query.aadhaar) {
    return await handleSearch(req, res, uid, userData);
  }
  
  return res.status(400).json({
    success: false,
    error: 'INVALID_ACTION',
    available_actions: Object.keys(handlers)
  });
}

// ===================== ✅ ADMIN KEY HANDLERS =====================

// ✅ ADMIN APPROVE WITHDRAWAL WITH KEY
async function handleAdminApproveWithdrawalKey(req, res, adminKey) {
  if (!adminKey) {
    return res.status(401).json({
      success: false,
      error: 'ADMIN_KEY_REQUIRED'
    });
  }
  
  const keyCheck = await verifyAdminKey(adminKey);
  if (!keyCheck.success) {
    return res.status(403).json({
      success: false,
      error: keyCheck.error || 'INVALID_ADMIN_KEY'
    });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { withdrawal_id, action, transaction_id } = req.body;
    
    if (!withdrawal_id || !action) {
      return res.status(400).json({ error: 'WITHDRAWAL_ID_AND_ACTION_REQUIRED' });
    }
    
    const withdrawalSnap = await adminDb.ref(`withdrawals/${withdrawal_id}`).once('value');
    const withdrawal = withdrawalSnap.val();
    
    if (!withdrawal) {
      return res.status(404).json({ error: 'WITHDRAWAL_NOT_FOUND' });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'ALREADY_PROCESSED' });
    }
    
    const userSnap = await adminDb.ref(`users/${withdrawal.user_id}`).once('value');
    const targetUser = userSnap.val();
    
    if (action === 'approve') {
      // Update withdrawal
      await adminDb.ref(`withdrawals/${withdrawal_id}`).update({
        status: 'approved',
        approved_by: 'admin_key',
        approved_at: new Date().toISOString(),
        transaction_id: transaction_id || null
      });
      
      // Update user
      await adminDb.ref(`users/${withdrawal.user_id}`).update({
        total_withdrawn: (targetUser.total_withdrawn || 0) + withdrawal.amount,
        pending_withdrawal: (targetUser.pending_withdrawal || 0) - withdrawal.amount
      });
      
      return res.json({
        success: true,
        message: 'Withdrawal approved via admin key'
      });
      
    } else if (action === 'reject') {
      await adminDb.ref(`withdrawals/${withdrawal_id}`).update({
        status: 'rejected',
        rejected_by: 'admin_key',
        rejected_at: new Date().toISOString()
      });
      
      // Return pending amount to user
      await adminDb.ref(`users/${withdrawal.user_id}`).update({
        pending_withdrawal: (targetUser.pending_withdrawal || 0) - withdrawal.amount
      });
      
      return res.json({
        success: true,
        message: 'Withdrawal rejected via admin key'
      });
    }
    
    return res.status(400).json({ error: 'INVALID_ACTION' });
    
  } catch (error) {
    console.error('Admin key withdrawal error:', error);
    return res.status(500).json({ error: 'WITHDRAWAL_APPROVAL_FAILED' });
  }
}

// ✅ ADMIN APPROVE PAYMENT WITH KEY
async function handleAdminApprovePaymentKey(req, res, adminKey) {
  if (!adminKey) {
    return res.status(401).json({
      success: false,
      error: 'ADMIN_KEY_REQUIRED'
    });
  }
  
  const keyCheck = await verifyAdminKey(adminKey);
  if (!keyCheck.success) {
    return res.status(403).json({
      success: false,
      error: keyCheck.error || 'INVALID_ADMIN_KEY'
    });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { payment_id, action, actual_credits } = req.body;
    
    const paymentSnap = await adminDb.ref(`payments/${payment_id}`).once('value');
    const payment = paymentSnap.val();
    
    if (!payment) {
      return res.status(404).json({ error: 'PAYMENT_NOT_FOUND' });
    }
    
    if (payment.status !== 'pending') {
      return res.status(400).json({ error: 'ALREADY_PROCESSED' });
    }
    
    if (action === 'approve') {
      const credits = actual_credits || payment.expected_credits;
      const userSnap = await adminDb.ref(`users/${payment.user_id}`).once('value');
      const targetUser = userSnap.val();
      
      // Update user credits
      await adminDb.ref(`users/${payment.user_id}`).update({
        credits: (targetUser.credits || 0) + parseFloat(credits),
        total_spent: (targetUser.total_spent || 0) + payment.amount
      });
      
      // Distribute commissions
      await distributeReferralCommissions(payment.user_id, payment.amount, payment.user_price);
      
      // Update payment
      await adminDb.ref(`payments/${payment_id}`).update({
        status: 'approved',
        approved_by: 'admin_key',
        approved_at: new Date().toISOString(),
        actual_credits: credits
      });
      
      return res.json({
        success: true,
        message: 'Payment approved via admin key',
        credits_added: credits
      });
      
    } else if (action === 'reject') {
      await adminDb.ref(`payments/${payment_id}`).update({
        status: 'rejected',
        rejected_by: 'admin_key',
        rejected_at: new Date().toISOString()
      });
      
      return res.json({
        success: true,
        message: 'Payment rejected via admin key'
      });
    }
    
    return res.status(400).json({ error: 'INVALID_ACTION' });
    
  } catch (error) {
    console.error('Admin payment key error:', error);
    return res.status(500).json({ error: 'PAYMENT_APPROVAL_FAILED' });
  }
}

// ===================== ORIGINAL HANDLER FUNCTIONS =====================

async function handleSignup(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { name, email, referral_code, uid } = req.body;
    
    if (!name || !email || !uid) {
      return res.status(400).json({ error: 'MISSING_FIELDS' });
    }
    
    // Check existing
    const userSnap = await adminDb.ref(`users/${uid}`).once('value');
    if (userSnap.exists()) {
      return res.status(400).json({ error: 'USER_EXISTS' });
    }
    
    // Process referral
    let referralChain = [];
    let referredBy = null;
    let userPrice = CONFIG.DIRECT_USER_PRICE;
    
    if (referral_code) {
      const referrerSnap = await adminDb.ref('users')
        .orderByChild('referral_code')
        .equalTo(referral_code.toUpperCase())
        .once('value');
      
      if (referrerSnap.exists()) {
        const referrerId = Object.keys(referrerSnap.val())[0];
        const referrer = referrerSnap.val()[referrerId];
        
        referredBy = referrerId;
        referralChain = [referrerId, ...(referrer.referral_chain || [])];
        userPrice = (await calculateUserPrice(referrerId)) + (referrer.commission_amount || CONFIG.DEFAULT_COMMISSION);
        
        await adminDb.ref(`referrals/${Date.now()}_${referrerId}`).set({
          referrer_id: referrerId,
          referred_user_id: uid,
          date: new Date().toISOString()
        });
        
        await adminDb.ref(`users/${referrerId}`).update({
          total_referrals: (referrer.total_referrals || 0) + 1
        });
      }
    }
    
    // Create user
    const userData = {
      uid, name, email,
      api_key: generateApiKey(uid),
      api_key_created_at: new Date().toISOString(),
      credits: CONFIG.SIGNUP_BONUS_CREDITS,
      purchase_price: userPrice,
      commission_amount: CONFIG.DEFAULT_COMMISSION,
      referral_code: generateReferralCode(),
      referred_by: referredBy,
      referral_chain: referralChain,
      total_earned: 0,
      referral_earnings: 0,
      indirect_earnings: 0,
      total_withdrawn: 0,
      pending_withdrawal: 0,
      user_type: 'regular',
      created_at: new Date().toISOString(),
      status: 'active',
      total_spent: 0,
      total_searches: 0,
      last_active: new Date().toISOString(),
      website_mode: false,
      domains: [],
      ip_whitelist: [],
      allow_direct_calls: true,
      signup_bonus_received: true,
      signup_bonus_amount: CONFIG.SIGNUP_BONUS_CREDITS
    };
    
    await adminDb.ref(`users/${uid}`).set(userData);
    
    return res.status(201).json({
      success: true,
      message: 'Account created with 10 free credits!',
      user: {
        name, email,
        credits: CONFIG.SIGNUP_BONUS_CREDITS,
        referral_code: userData.referral_code,
        api_key: userData.api_key
      }
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ error: 'SIGNUP_FAILED', message: error.message });
  }
}

async function handleGetProfile(req, res, uid, userData) {
  try {
    const currentPrice = await calculateUserPrice(uid);
    const referralChain = await getReferralChain(uid);
    
    const downlineSnap = await adminDb.ref('users')
      .orderByChild('referred_by')
      .equalTo(uid)
      .once('value');
    
    return res.json({
      success: true,
      profile: {
        uid, name: userData.name, email: userData.email,
        user_type: userData.user_type, credits: userData.credits || 0,
        api_key: userData.api_key, created_at: userData.created_at
      },
      pricing: {
        your_price: currentPrice,
        your_commission: userData.commission_amount || CONFIG.DEFAULT_COMMISSION
      },
      referral: {
        your_code: userData.referral_code,
        referred_by: userData.referred_by,
        chain: referralChain,
        total_referrals: Object.keys(downlineSnap.val() || {}).length
      },
      earnings: {
        total_earned: userData.total_earned || 0,
        total_withdrawn: userData.total_withdrawn || 0,
        available: (userData.total_earned || 0) - (userData.total_withdrawn || 0)
      },
      id_visibility: {
        can_see_full_id: (userData.total_spent || 0) >= CONFIG.ID_VISIBILITY_THRESHOLD,
        amount_spent: userData.total_spent || 0,
        required: CONFIG.ID_VISIBILITY_THRESHOLD
      },
      website_settings: userData.user_type === 'developer' ? {
        enabled: userData.website_mode || false,
        domains: userData.domains || [],
        ip_whitelist: userData.ip_whitelist || []
      } : null
    });
    
  } catch (error) {
    console.error('Profile error:', error);
    return res.status(500).json({ error: 'PROFILE_FETCH_FAILED' });
  }
}

async function handleSearch(req, res, uid, userData) {
  try {
    const { number, aadhaar } = req.query;
    
    if (!number && !aadhaar) {
      return res.status(400).json({ error: 'INPUT_REQUIRED' });
    }
    
    if (userData.credits < CONFIG.COST_PER_SEARCH) {
      return res.status(400).json({
        error: 'INSUFFICIENT_CREDITS',
        credits_available: userData.credits,
        required: CONFIG.COST_PER_SEARCH
      });
    }
    
    // Deduct credit
    const newCredits = userData.credits - CONFIG.COST_PER_SEARCH;
    await adminDb.ref(`users/${uid}`).update({
      credits: newCredits,
      total_searches: (userData.total_searches || 0) + 1,
      last_active: new Date().toISOString()
    });
    
    // Call external API
    const apiUrl = number 
      ? `https://happy-all-api.vercel.app/api/aggregate?number=${number}`
      : `https://happy-all-api.vercel.app/api/aggregate?aadhaar=${aadhaar}`;
    
    const response = await fetch(apiUrl);
    const data = await response.json();
    
    // Mask IDs if needed
    const canSeeFullId = (userData.total_spent || 0) >= CONFIG.ID_VISIBILITY_THRESHOLD;
    let processedData = data;
    
    if (!canSeeFullId && data.success && data.data) {
      processedData = JSON.parse(JSON.stringify(data));
      
      const maskFields = ['aadhaar_numbers', 'pan_number', 'voter_id', 'driving_license'];
      maskFields.forEach(field => {
        if (processedData.data[field]) {
          if (Array.isArray(processedData.data[field])) {
            processedData.data[field] = processedData.data[field].map(maskIdNumber);
          } else {
            processedData.data[field] = maskIdNumber(processedData.data[field]);
          }
        }
      });
    }
    
    // Log search
    await adminDb.ref(`search_logs/${Date.now()}_${uid}`).set({
      user_id: uid,
      query: number || aadhaar,
      credits_used: CONFIG.COST_PER_SEARCH,
      timestamp: new Date().toISOString()
    });
    
    return res.json({
      success: true,
      data: processedData,
      credits: {
        used: CONFIG.COST_PER_SEARCH,
        remaining: newCredits
      },
      id_visibility: {
        full_access: canSeeFullId,
        amount_spent: userData.total_spent || 0,
        required: CONFIG.ID_VISIBILITY_THRESHOLD
      }
    });
    
  } catch (error) {
    console.error('Search error:', error);
    
    // Refund on error
    await adminDb.ref(`users/${uid}`).update({
      credits: userData.credits
    });
    
    return res.status(500).json({ error: 'SEARCH_FAILED', message: error.message });
  }
}

async function handleSubmitPayment(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { amount, utr_number } = req.body;
    
    if (!amount || amount < CONFIG.MIN_PURCHASE) {
      return res.status(400).json({
        error: 'INVALID_AMOUNT',
        min_amount: CONFIG.MIN_PURCHASE
      });
    }
    
    const userPrice = await calculateUserPrice(uid);
    const expectedCredits = amount / userPrice;
    
    const paymentId = `pay_${Date.now()}_${uid}`;
    
    await adminDb.ref(`payments/${paymentId}`).set({
      payment_id: paymentId,
      user_id: uid,
      user_name: userData.name,
      amount,
      utr_number,
      user_price: userPrice,
      expected_credits: expectedCredits,
      status: 'pending',
      created_at: new Date().toISOString()
    });
    
    return res.json({
      success: true,
      message: 'Payment submitted for approval',
      payment_id: paymentId,
      expected_credits: expectedCredits.toFixed(2)
    });
    
  } catch (error) {
    console.error('Payment error:', error);
    return res.status(500).json({ error: 'PAYMENT_FAILED' });
  }
}

async function handleCheckPayment(req, res, uid, userData) {
  try {
    const { payment_id } = req.query;
    
    if (payment_id) {
      const paymentSnap = await adminDb.ref(`payments/${payment_id}`).once('value');
      const payment = paymentSnap.val();
      
      if (!payment || payment.user_id !== uid) {
        return res.status(404).json({ error: 'PAYMENT_NOT_FOUND' });
      }
      
      return res.json({ success: true, payment });
    }
    
    // Get all payments
    const paymentsSnap = await adminDb.ref('payments')
      .orderByChild('user_id')
      .equalTo(uid)
      .once('value');
    
    return res.json({
      success: true,
      payments: Object.values(paymentsSnap.val() || {}).reverse()
    });
    
  } catch (error) {
    console.error('Check payment error:', error);
    return res.status(500).json({ error: 'PAYMENT_CHECK_FAILED' });
  }
}

async function handleUseReferral(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { referral_code } = req.body;
    
    if (!referral_code) {
      return res.status(400).json({ error: 'REFERRAL_CODE_REQUIRED' });
    }
    
    if (userData.referred_by) {
      return res.status(400).json({ error: 'ALREADY_REFERRED' });
    }
    
    const referrerSnap = await adminDb.ref('users')
      .orderByChild('referral_code')
      .equalTo(referral_code.toUpperCase())
      .once('value');
    
    if (!referrerSnap.exists()) {
      return res.status(404).json({ error: 'INVALID_REFERRAL_CODE' });
    }
    
    const referrerId = Object.keys(referrerSnap.val())[0];
    const referrer = referrerSnap.val()[referrerId];
    
    if (referrerId === uid) {
      return res.status(400).json({ error: 'SELF_REFERRAL' });
    }
    
    const referrerChain = await getReferralChain(referrerId);
    const newChain = [referrerId, ...referrerChain.map(r => r.user_id)];
    const newPrice = (await calculateUserPrice(referrerId)) + (referrer.commission_amount || CONFIG.DEFAULT_COMMISSION);
    
    await adminDb.ref(`users/${uid}`).update({
      referred_by: referrerId,
      referral_chain: newChain,
      purchase_price: newPrice
    });
    
    await adminDb.ref(`users/${referrerId}`).update({
      total_referrals: (referrer.total_referrals || 0) + 1
    });
    
    return res.json({
      success: true,
      message: 'Referral applied!',
      new_price: newPrice,
      referrer_name: referrer.name
    });
    
  } catch (error) {
    console.error('Referral error:', error);
    return res.status(500).json({ error: 'REFERRAL_FAILED' });
  }
}

async function handleSetCommission(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { commission_amount } = req.body;
    
    if (!commission_amount || 
        commission_amount < CONFIG.MIN_COMMISSION || 
        commission_amount > CONFIG.MAX_COMMISSION) {
      return res.status(400).json({
        error: 'INVALID_COMMISSION',
        min: CONFIG.MIN_COMMISSION,
        max: CONFIG.MAX_COMMISSION
      });
    }
    
    await adminDb.ref(`users/${uid}`).update({
      commission_amount: parseFloat(commission_amount)
    });
    
    return res.json({
      success: true,
      message: 'Commission updated',
      new_commission: commission_amount
    });
    
  } catch (error) {
    console.error('Commission error:', error);
    return res.status(500).json({ error: 'COMMISSION_UPDATE_FAILED' });
  }
}

async function handleRotateApiKey(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const oldKey = userData.api_key;
    const newKey = generateApiKey(uid);
    
    // Store old key
    await adminDb.ref(`api_key_history/${Date.now()}_${uid}`).set({
      user_id: uid,
      old_api_key: oldKey,
      new_api_key: newKey,
      rotated_at: new Date().toISOString()
    });
    
    // Update user
    await adminDb.ref(`users/${uid}`).update({
      api_key: newKey,
      api_key_created_at: new Date().toISOString(),
      api_key_rotations: (userData.api_key_rotations || 0) + 1
    });
    
    return res.json({
      success: true,
      message: 'API Key rotated',
      new_api_key: newKey
    });
    
  } catch (error) {
    console.error('API key rotation error:', error);
    return res.status(500).json({ error: 'KEY_ROTATION_FAILED' });
  }
}

async function handleManageIPWhitelist(req, res, uid, userData) {
  if (req.method === 'GET') {
    const whitelist = userData.ip_whitelist || [];
    return res.json({
      success: true,
      ip_whitelist: whitelist,
      current_ip: getClientIP(req)
    });
  }
  
  if (req.method === 'POST') {
    try {
      const { action, ip_address } = req.body;
      let whitelist = userData.ip_whitelist || [];
      
      if (action === 'add') {
        if (whitelist.length >= 10) {
          return res.status(400).json({ error: 'LIMIT_EXCEEDED', max: 10 });
        }
        if (!whitelist.includes(ip_address)) {
          whitelist.push(ip_address);
        }
      } else if (action === 'remove') {
        whitelist = whitelist.filter(ip => ip !== ip_address);
      } else if (action === 'clear') {
        whitelist = [];
      }
      
      await adminDb.ref(`users/${uid}`).update({ ip_whitelist: whitelist });
      
      return res.json({
        success: true,
        message: 'IP whitelist updated',
        ip_whitelist: whitelist
      });
      
    } catch (error) {
      console.error('IP whitelist error:', error);
      return res.status(500).json({ error: 'IP_WHITELIST_FAILED' });
    }
  }
  
  return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}

async function handleApiKeyHistory(req, res, uid, userData) {
  try {
    const historySnap = await adminDb.ref('api_key_history')
      .orderByChild('user_id')
      .equalTo(uid)
      .once('value');
    
    const history = Object.values(historySnap.val() || {}).map(record => ({
      rotated_at: record.rotated_at,
      old_key_prefix: record.old_api_key?.substring(0, 10) + '...',
      new_key_prefix: record.new_api_key?.substring(0, 10) + '...'
    })).reverse();
    
    return res.json({
      success: true,
      history,
      total_rotations: userData.api_key_rotations || 0
    });
    
  } catch (error) {
    console.error('API history error:', error);
    return res.status(500).json({ error: 'HISTORY_FETCH_FAILED' });
  }
}

async function handleUpdateBankDetails(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { bank_name, account_number, ifsc_code, upi_id } = req.body;
    
    const bankDetails = bank_name ? {
      bank_name,
      account_number,
      ifsc_code,
      verified: false
    } : null;
    
    await adminDb.ref(`users/${uid}`).update({
      bank_details: bankDetails,
      upi_id: upi_id || null
    });
    
    return res.json({
      success: true,
      message: 'Payment details updated'
    });
    
  } catch (error) {
    console.error('Bank details error:', error);
    return res.status(500).json({ error: 'BANK_DETAILS_FAILED' });
  }
}

async function handleRequestWithdrawal(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { amount } = req.body;
    
    const available = (userData.total_earned || 0) - (userData.total_withdrawn || 0);
    
    if (!amount || amount < CONFIG.MIN_WITHDRAWAL || amount > available) {
      return res.status(400).json({
        error: 'INVALID_AMOUNT',
        min_amount: CONFIG.MIN_WITHDRAWAL,
        available: available
      });
    }
    
    if (!userData.bank_details && !userData.upi_id) {
      return res.status(400).json({
        error: 'NO_PAYMENT_METHOD',
        message: 'Please add bank or UPI details first'
      });
    }
    
    const withdrawalId = `with_${Date.now()}_${uid}`;
    
    await adminDb.ref(`withdrawals/${withdrawalId}`).set({
      withdrawal_id: withdrawalId,
      user_id: uid,
      user_name: userData.name,
      amount,
      payment_method: userData.bank_details ? 'bank' : 'upi',
      details: userData.bank_details || userData.upi_id,
      status: 'pending',
      requested_at: new Date().toISOString()
    });
    
    await adminDb.ref(`users/${uid}`).update({
      pending_withdrawal: (userData.pending_withdrawal || 0) + amount
    });
    
    return res.json({
      success: true,
      message: 'Withdrawal request submitted',
      withdrawal_id: withdrawalId
    });
    
  } catch (error) {
    console.error('Withdrawal error:', error);
    return res.status(500).json({ error: 'WITHDRAWAL_FAILED' });
  }
}

async function handleReferralNetwork(req, res, uid, userData) {
  try {
    // Get direct referrals
    const directSnap = await adminDb.ref('users')
      .orderByChild('referred_by')
      .equalTo(uid)
      .once('value');
    
    const directRefs = directSnap.val() || {};
    
    // Get indirect referrals (through chain)
    let indirectRefs = {};
    for (const directId of Object.keys(directRefs)) {
      const indirectSnap = await adminDb.ref('users')
        .orderByChild('referred_by')
        .equalTo(directId)
        .once('value');
      
      indirectRefs = { ...indirectRefs, ...(indirectSnap.val() || {}) };
    }
    
    return res.json({
      success: true,
      network: {
        direct_referrals: Object.keys(directRefs).length,
        indirect_referrals: Object.keys(indirectRefs).length,
        total_earned: userData.total_earned || 0,
        referral_earnings: userData.referral_earnings || 0,
        indirect_earnings: userData.indirect_earnings || 0
      },
      direct_users: Object.values(directRefs).map(user => ({
        name: user.name,
        email: user.email,
        joined: user.created_at,
        status: user.status
      }))
    });
    
  } catch (error) {
    console.error('Network error:', error);
    return res.status(500).json({ error: 'NETWORK_FETCH_FAILED' });
  }
}

async function handleEarningsReport(req, res, uid, userData) {
  try {
    const commissionsSnap = await adminDb.ref('commissions')
      .orderByChild('referrer')
      .equalTo(uid)
      .once('value');
    
    const commissions = commissionsSnap.val() || {};
    const today = new Date().toISOString().split('T')[0];
    
    const todayEarnings = Object.values(commissions)
      .filter(c => c.date.startsWith(today))
      .reduce((sum, c) => sum + (c.amount || 0), 0);
    
    const weeklyEarnings = Object.values(commissions)
      .filter(c => {
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        return new Date(c.date) > weekAgo;
      })
      .reduce((sum, c) => sum + (c.amount || 0), 0);
    
    return res.json({
      success: true,
      earnings: {
        total: userData.total_earned || 0,
        referral: userData.referral_earnings || 0,
        indirect: userData.indirect_earnings || 0,
        today: todayEarnings,
        this_week: weeklyEarnings,
        withdrawn: userData.total_withdrawn || 0,
        pending: userData.pending_withdrawal || 0,
        available: (userData.total_earned || 0) - (userData.total_withdrawn || 0)
      }
    });
    
  } catch (error) {
    console.error('Earnings error:', error);
    return res.status(500).json({ error: 'EARNINGS_FETCH_FAILED' });
  }
}

async function handleWithdrawalHistory(req, res, uid, userData) {
  try {
    const withdrawalsSnap = await adminDb.ref('withdrawals')
      .orderByChild('user_id')
      .equalTo(uid)
      .once('value');
    
    const withdrawals = Object.values(withdrawalsSnap.val() || {}).reverse();
    
    return res.json({
      success: true,
      withdrawals: withdrawals.map(w => ({
        id: w.withdrawal_id,
        amount: w.amount,
        status: w.status,
        date: w.requested_at,
        payment_method: w.payment_method
      }))
    });
    
  } catch (error) {
    console.error('Withdrawal history error:', error);
    return res.status(500).json({ error: 'HISTORY_FETCH_FAILED' });
  }
}

async function handleCreateDeveloper(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  try {
    const { user_id, domains, website_mode } = req.body;
    
    if (!user_id) {
      return res.status(400).json({ error: 'USER_ID_REQUIRED' });
    }
    
    const targetSnap = await adminDb.ref(`users/${user_id}`).once('value');
    const targetUser = targetSnap.val();
    
    if (!targetUser) {
      return res.status(404).json({ error: 'USER_NOT_FOUND' });
    }
    
    await adminDb.ref(`users/${user_id}`).update({
      user_type: 'developer',
      purchase_price: CONFIG.DEVELOPER_PRICE,
      developer_since: new Date().toISOString(),
      domains: domains || [],
      website_mode: website_mode || false,
      allow_direct_calls: true
    });
    
    return res.json({
      success: true,
      message: 'User upgraded to developer'
    });
    
  } catch (error) {
    console.error('Developer creation error:', error);
    return res.status(500).json({ error: 'DEVELOPER_CREATION_FAILED' });
  }
}

async function handleManageDomains(req, res, uid, userData) {
  if (userData.user_type !== 'developer') {
    return res.status(403).json({ error: 'DEVELOPER_ONLY' });
  }
  
  if (req.method === 'GET') {
    return res.json({
      success: true,
      domains: userData.domains || [],
      max_domains: CONFIG.WEBSITE_MODE.MAX_DOMAINS
    });
  }
  
  if (req.method === 'POST') {
    try {
      const { action, domain } = req.body;
      let domains = userData.domains || [];
      
      if (action === 'add') {
        if (domains.length >= CONFIG.WEBSITE_MODE.MAX_DOMAINS) {
          return res.status(400).json({ error: 'DOMAIN_LIMIT_REACHED' });
        }
        
        const normalized = normalizeDomain(domain);
        if (!domains.includes(normalized)) {
          domains.push(normalized);
        }
      } else if (action === 'remove') {
        domains = domains.filter(d => d !== domain);
      }
      
      await adminDb.ref(`users/${uid}`).update({ domains });
      
      return res.json({
        success: true,
        message: 'Domains updated',
        domains
      });
      
    } catch (error) {
      console.error('Domain error:', error);
      return res.status(500).json({ error: 'DOMAIN_MANAGEMENT_FAILED' });
    }
  }
  
  return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}

async function handleWebsiteSettings(req, res, uid, userData) {
  if (userData.user_type !== 'developer') {
    return res.status(403).json({ error: 'DEVELOPER_ONLY' });
  }
  
  if (req.method === 'GET') {
    return res.json({
      success: true,
      settings: {
        website_mode: userData.website_mode || false,
        domains: userData.domains || [],
        allow_direct_calls: userData.allow_direct_calls !== false
      }
    });
  }
  
  if (req.method === 'POST') {
    try {
      const { website_mode, allow_direct_calls } = req.body;
      const updates = {};
      
      if (website_mode !== undefined) updates.website_mode = website_mode;
      if (allow_direct_calls !== undefined) updates.allow_direct_calls = allow_direct_calls;
      
      await adminDb.ref(`users/${uid}`).update(updates);
      
      return res.json({
        success: true,
        message: 'Settings updated',
        settings: updates
      });
      
    } catch (error) {
      console.error('Settings error:', error);
      return res.status(500).json({ error: 'SETTINGS_UPDATE_FAILED' });
    }
  }
  
  return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}

async function handleBulkSearch(req, res, uid, userData) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { numbers, aadhaars } = req.body;
    const items = numbers || aadhaars;
    const type = numbers ? 'phone' : 'aadhaar';
    
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }
    
    if (items.length > CONFIG.MAX_RESULTS) {
      return res.status(400).json({ 
        error: 'LIMIT_EXCEEDED',
        max: CONFIG.MAX_RESULTS 
      });
    }
    
    const requiredCredits = items.length * CONFIG.COST_PER_SEARCH;
    
    if (userData.credits < requiredCredits) {
      return res.status(400).json({
        error: 'INSUFFICIENT_CREDITS',
        required: requiredCredits,
        available: userData.credits
      });
    }
    
    // Process searches
    const results = [];
    for (const item of items) {
      try {
        const apiUrl = type === 'phone'
          ? `https://happy-all-api.vercel.app/api/aggregate?number=${item}`
          : `https://happy-all-api.vercel.app/api/aggregate?aadhaar=${item}`;
        
        const response = await fetch(apiUrl);
        const data = await response.json();
        results.push({ query: item, success: true, data });
      } catch (error) {
        results.push({ query: item, success: false, error: error.message });
      }
    }
    
    // Update credits
    await adminDb.ref(`users/${uid}`).update({
      credits: userData.credits - requiredCredits,
      total_searches: (userData.total_searches || 0) + items.length
    });
    
    return res.json({
      success: true,
      results,
      summary: {
        total: items.length,
        successful: results.filter(r => r.success).length,
        credits_used: requiredCredits
      }
    });
    
  } catch (error) {
    console.error('Bulk search error:', error);
    return res.status(500).json({ error: 'BULK_SEARCH_FAILED' });
  }
}

async function handleSearchHistory(req, res, uid, userData) {
  try {
    const historySnap = await adminDb.ref('search_logs')
      .orderByChild('user_id')
      .equalTo(uid)
      .limitToLast(50)
      .once('value');
    
    const history = Object.values(historySnap.val() || {}).reverse();
    
    return res.json({
      success: true,
      history: history.map(h => ({
        query: h.query,
        credits_used: h.credits_used,
        timestamp: h.timestamp
      }))
    });
    
  } catch (error) {
    console.error('History error:', error);
    return res.status(500).json({ error: 'HISTORY_FETCH_FAILED' });
  }
}

// ===================== ADMIN HANDLERS (ORIGINAL) =====================
async function handleAdminApprovePayment(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { payment_id, action, actual_credits } = req.body;
    
    const paymentSnap = await adminDb.ref(`payments/${payment_id}`).once('value');
    const payment = paymentSnap.val();
    
    if (!payment) {
      return res.status(404).json({ error: 'PAYMENT_NOT_FOUND' });
    }
    
    if (payment.status !== 'pending') {
      return res.status(400).json({ error: 'ALREADY_PROCESSED' });
    }
    
    if (action === 'approve') {
      const credits = actual_credits || payment.expected_credits;
      const userSnap = await adminDb.ref(`users/${payment.user_id}`).once('value');
      const targetUser = userSnap.val();
      
      // Update user credits
      await adminDb.ref(`users/${payment.user_id}`).update({
        credits: (targetUser.credits || 0) + parseFloat(credits),
        total_spent: (targetUser.total_spent || 0) + payment.amount
      });
      
      // Distribute commissions
      await distributeReferralCommissions(payment.user_id, payment.amount, payment.user_price);
      
      // Update payment
      await adminDb.ref(`payments/${payment_id}`).update({
        status: 'approved',
        approved_by: uid,
        approved_at: new Date().toISOString(),
        actual_credits: credits
      });
      
      return res.json({
        success: true,
        message: 'Payment approved',
        credits_added: credits
      });
      
    } else if (action === 'reject') {
      await adminDb.ref(`payments/${payment_id}`).update({
        status: 'rejected',
        rejected_by: uid,
        rejected_at: new Date().toISOString()
      });
      
      return res.json({
        success: true,
        message: 'Payment rejected'
      });
    }
    
    return res.status(400).json({ error: 'INVALID_ACTION' });
    
  } catch (error) {
    console.error('Admin payment error:', error);
    return res.status(500).json({ error: 'PAYMENT_APPROVAL_FAILED' });
  }
}

async function handleAdminApproveWithdrawal(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { withdrawal_id, action, transaction_id } = req.body;
    
    const withdrawalSnap = await adminDb.ref(`withdrawals/${withdrawal_id}`).once('value');
    const withdrawal = withdrawalSnap.val();
    
    if (!withdrawal) {
      return res.status(404).json({ error: 'WITHDRAWAL_NOT_FOUND' });
    }
    
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'ALREADY_PROCESSED' });
    }
    
    const userSnap = await adminDb.ref(`users/${withdrawal.user_id}`).once('value');
    const targetUser = userSnap.val();
    
    if (action === 'approve') {
      // Update withdrawal
      await adminDb.ref(`withdrawals/${withdrawal_id}`).update({
        status: 'approved',
        approved_by: uid,
        approved_at: new Date().toISOString(),
        transaction_id
      });
      
      // Update user
      await adminDb.ref(`users/${withdrawal.user_id}`).update({
        total_withdrawn: (targetUser.total_withdrawn || 0) + withdrawal.amount,
        pending_withdrawal: (targetUser.pending_withdrawal || 0) - withdrawal.amount
      });
      
      return res.json({
        success: true,
        message: 'Withdrawal approved'
      });
      
    } else if (action === 'reject') {
      await adminDb.ref(`withdrawals/${withdrawal_id}`).update({
        status: 'rejected',
        rejected_by: uid,
        rejected_at: new Date().toISOString()
      });
      
      // Return pending amount to user
      await adminDb.ref(`users/${withdrawal.user_id}`).update({
        pending_withdrawal: (targetUser.pending_withdrawal || 0) - withdrawal.amount
      });
      
      return res.json({
        success: true,
        message: 'Withdrawal rejected'
      });
    }
    
    return res.status(400).json({ error: 'INVALID_ACTION' });
    
  } catch (error) {
    console.error('Admin withdrawal error:', error);
    return res.status(500).json({ error: 'WITHDRAWAL_APPROVAL_FAILED' });
  }
}

async function handleAdminAdjustBalance(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { user_id, credits, reason } = req.body;
    
    if (!user_id || credits === undefined) {
      return res.status(400).json({ error: 'USER_ID_AND_CREDITS_REQUIRED' });
    }
    
    const targetSnap = await adminDb.ref(`users/${user_id}`).once('value');
    const targetUser = targetSnap.val();
    
    if (!targetUser) {
      return res.status(404).json({ error: 'USER_NOT_FOUND' });
    }
    
    const newCredits = (targetUser.credits || 0) + parseFloat(credits);
    
    await adminDb.ref(`users/${user_id}`).update({
      credits: newCredits
    });
    
    // Log adjustment
    await adminDb.ref(`admin_logs/${Date.now()}_${user_id}`).set({
      admin_id: uid,
      user_id,
      credits_adjusted: credits,
      reason,
      timestamp: new Date().toISOString()
    });
    
    return res.json({
      success: true,
      message: 'Balance adjusted',
      new_balance: newCredits
    });
    
  } catch (error) {
    console.error('Balance adjustment error:', error);
    return res.status(500).json({ error: 'BALANCE_ADJUSTMENT_FAILED' });
  }
}

async function handleAdminAllUsers(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  try {
    const usersSnap = await adminDb.ref('users').once('value');
    const users = usersSnap.val() || {};
    
    const userList = Object.entries(users).map(([id, user]) => ({
      id,
      name: user.name,
      email: user.email,
      user_type: user.user_type,
      credits: user.credits || 0,
      total_spent: user.total_spent || 0,
      total_earned: user.total_earned || 0,
      status: user.status,
      created_at: user.created_at
    }));
    
    return res.json({
      success: true,
      users: userList,
      total: userList.length
    });
    
  } catch (error) {
    console.error('Admin users error:', error);
    return res.status(500).json({ error: 'USERS_FETCH_FAILED' });
  }
}

async function handleAdminPendingRequests(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  try {
    // Pending payments
    const paymentsSnap = await adminDb.ref('payments')
      .orderByChild('status')
      .equalTo('pending')
      .once('value');
    
    // Pending withdrawals
    const withdrawalsSnap = await adminDb.ref('withdrawals')
      .orderByChild('status')
      .equalTo('pending')
      .once('value');
    
    return res.json({
      success: true,
      pending: {
        payments: Object.values(paymentsSnap.val() || {}),
        withdrawals: Object.values(withdrawalsSnap.val() || {})
      }
    });
    
  } catch (error) {
    console.error('Pending requests error:', error);
    return res.status(500).json({ error: 'PENDING_REQUESTS_FAILED' });
  }
}

async function handleAdminSystemStats(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  try {
    const [usersSnap, paymentsSnap, withdrawalsSnap] = await Promise.all([
      adminDb.ref('users').once('value'),
      adminDb.ref('payments').once('value'),
      adminDb.ref('withdrawals').once('value')
    ]);
    
    const users = Object.values(usersSnap.val() || {});
    const payments = Object.values(paymentsSnap.val() || {});
    const withdrawals = Object.values(withdrawalsSnap.val() || {});
    
    const totalRevenue = payments
      .filter(p => p.status === 'approved')
      .reduce((sum, p) => sum + (p.amount || 0), 0);
    
    const totalWithdrawn = withdrawals
      .filter(w => w.status === 'approved')
      .reduce((sum, w) => sum + (w.amount || 0), 0);
    
    return res.json({
      success: true,
      stats: {
        total_users: users.length,
        regular_users: users.filter(u => u.user_type === 'regular').length,
        developers: users.filter(u => u.user_type === 'developer').length,
        total_revenue: totalRevenue,
        total_withdrawn: totalWithdrawn,
        pending_withdrawals: withdrawals
          .filter(w => w.status === 'pending')
          .reduce((sum, w) => sum + (w.amount || 0), 0),
        total_credits: users.reduce((sum, u) => sum + (u.credits || 0), 0),
        total_searches: users.reduce((sum, u) => sum + (u.total_searches || 0), 0)
      }
    });
    
  } catch (error) {
    console.error('System stats error:', error);
    return res.status(500).json({ error: 'STATS_FETCH_FAILED' });
  }
}

async function handleAdminManageDeveloper(req, res, uid, userData) {
  if (userData.user_type !== 'admin') {
    return res.status(403).json({ error: 'ADMIN_REQUIRED' });
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  
  try {
    const { user_id, action, domains, website_mode } = req.body;
    
    if (!user_id || !action) {
      return res.status(400).json({ error: 'USER_ID_AND_ACTION_REQUIRED' });
    }
    
    const targetSnap = await adminDb.ref(`users/${user_id}`).once('value');
    const targetUser = targetSnap.val();
    
    if (!targetUser) {
      return res.status(404).json({ error: 'USER_NOT_FOUND' });
    }
    
    if (action === 'update') {
      const updates = {};
      if (domains !== undefined) updates.domains = domains;
      if (website_mode !== undefined) updates.website_mode = website_mode;
      
      await adminDb.ref(`users/${user_id}`).update(updates);
      
      return res.json({
        success: true,
        message: 'Developer updated',
        updates
      });
    }
    
    if (action === 'disable') {
      await adminDb.ref(`users/${user_id}`).update({
        user_type: 'regular',
        purchase_price: CONFIG.DIRECT_USER_PRICE
      });
      
      return res.json({
        success: true,
        message: 'Developer downgraded to regular user'
      });
    }
    
    return res.status(400).json({ error: 'INVALID_ACTION' });
    
  } catch (error) {
    console.error('Developer management error:', error);
    return res.status(500).json({ error: 'DEVELOPER_MANAGEMENT_FAILED' });
  }
}
