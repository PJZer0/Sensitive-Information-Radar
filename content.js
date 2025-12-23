// content.js - 智能监控输入框中的敏感信息，支持告警等级设置

(function() {
  'use strict';

  // ========== 全局状态 ==========
  let extensionSettings = {
    enableAutoBlock: true,
    alertLevel: 'all', // 'high', 'medium', 'low', 'all'
    enableContext: true
  };
  
  const observedInputs = new WeakMap(); // 跟踪已监控的输入框
  let lastScanTime = 0;
  const SCAN_INTERVAL = 1000; // 1秒扫描间隔，避免性能问题
  const WARNING_TIMEOUT = 5000; // 警告显示时间

  // ========== 完整敏感信息检测规则 ==========
  const SENSITIVE_PATTERNS = {
    'API Key': /(?:api[_-]?(?:key|token)|access[_-]?token)["'\s]*[:=][\s]*["']([A-Za-z0-9\-_]{20,})["']/gi,
    'Secret': /(?:secret|secret[_-]?key|client[_-]?secret)["'\s]*[:=][\s]*["']([A-Za-z0-9\-_]{20,})["']/gi,
    'Swagger UI': /(?:swagger-ui\.html|swaggerUi|swaggerVersion|swagger_url|swagger_endpoint)/gi,
    '阿里云AK': /LTAI[A-Za-z0-9]{12,20}/g,
    '腾讯云AK': /AKID[A-Za-z0-9]{13,20}/g,
    '百度云AK': /AK[A-Za-z0-9]{10,40}/g,
    '京东云': /JDC_[A-Z0-9]{28,32}/g,
    '火山引擎': /AKLT[a-zA-Z0-9-_]{0,252}/g,
    '明文ID参数': /\b(?:id|user_id|account_id|customer_id)=(\d{4,})\b(?![-_\\/])/gi,
    'JSON-ID参数': /(?:"(?:id|[a-z]*_id)"\s*:\s*(\d{4,}))/gi,
    'Shiro特征': /(?:rememberMe|deleteMe)=/gi,
    'URL跳转参数': /[?&](?:goto|redirect|redirect_to|redirect_url|jump|jump_to|to|target|return|returnUrl|callback)=[^&#]*/gi,
    '敏感管理路径': /\/(?:admin|manage|manager|system|console|dashboard|control|panel|cms|wp-admin)(?:\/|$)/gi,
    '数据库连接': /jdbc:[a-z:]+:\/\/[a-z0-9.\-_:;=@?,&]+|mongodb:\/\/[a-z0-9.\-_:;=@?,&]+/gi,
    '密码字段': /(?:pass|pwd|password)["'\s]*[:=][\s]*["'][^"']{1,20}["']/gi,
    '账号字段': /(?:user|username|account)["'\s]*[:=][\s]*["'][^"']{1,30}["']/gi,
    '车牌号': /[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]/g,
    '手机号': /\b(?:\+?86)?1[3-9]\d{9}\b/g,
    '身份证': /\b\d{6}(?:18|19|20)?\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])\d{3}[\dXx]\b/g,
    '邮箱': /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    '银行卡号': /\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16,19}\b/g,
    'JWT Token': /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gi,
    'AWS Key': /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    'Google API': /\bAIza[0-9A-Za-z_-]{35}\b/g,
    'GitHub Token': /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
    'RSA私钥': /-----BEGIN RSA PRIVATE KEY-----/g,
    'SSH私钥': /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    'PEM私钥': /-----BEGIN PRIVATE KEY-----/g,
    '内网IP': /\b(?:127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
    'flag!!!': /\bflag\{|666c6167|Zmxh|&#102;|464C4147\b/gi,
    'ak sk': /(?:access[-_]?key[-_]?id|access[-_]?key|secret[-_]?access[-_]?key)["'\s]*[:=][\s]*["']?([A-Za-z0-9\-_\/+]{15,})["']?/gi,
    '云安全': /(?:access_key|access_token|admin_pass|api_key|api_secret|app_secret|auth_token|aws_access|aws_secret|consumer_secret|db_password|password|secret|token)["'\s]*[:=][\s]*["']?([A-Za-z0-9\-_\/+]{8,})["']?/gi,
    '加密算法': /\b(?:md5|sha1|sha256|aes|des|rc4|base64|bs4)\b/gi
  };
  
  // 风险等级分类
  const RISK_LEVELS = {
    high: [
      'API Key', 'Secret', '阿里云AK', '腾讯云AK', '百度云AK', '京东云', '火山引擎',
      'Shiro特征', '数据库连接', '身份证', 'JWT Token', 'AWS Key', 'Google API',
      'GitHub Token', 'RSA私钥', 'SSH私钥', 'PEM私钥', 'flag!!!', 'ak sk', '云安全'
    ],
    medium: [
      '明文ID参数', 'JSON-ID参数', '密码字段', '内网IP', '敏感管理路径'
    ],
    low: [
      'Swagger UI', 'URL跳转参数', '账号字段', '加密算法', '车牌号'
    ],
    info: ['邮箱', '手机号', '银行卡号']
  };

  // 风险级别到数值的映射（用于比较）
  const RISK_VALUES = {
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };

  // 风险颜色
  const RISK_COLORS = {
    high: '#e74c3c',
    medium: '#e67e22',
    low: '#2ecc71',
    info: '#3498db'
  };

  function getRiskLevel(category) {
    if (RISK_LEVELS.high.includes(category)) return 'high';
    if (RISK_LEVELS.medium.includes(category)) return 'medium';
    if (RISK_LEVELS.low.includes(category)) return 'low';
    return 'info';
  }

  function getRiskColor(category) {
    const level = getRiskLevel(category);
    return RISK_COLORS[level] || RISK_COLORS.info;
  }

  // 检测敏感信息（根据告警等级过滤）
  function detectSensitiveData(data) {
    if (!extensionSettings.enableAutoBlock) return null;
    
    const results = {};
    let hasSensitiveData = false;
    let highestRiskLevel = 'info';
    
    // 转换为字符串
    if (typeof data !== 'string') {
      data = String(data);
    }
    
    // 确定最小风险级别（基于告警等级设置）
    let minRiskValue;
    switch(extensionSettings.alertLevel) {
      case 'high': minRiskValue = RISK_VALUES.high; break;
      case 'medium': minRiskValue = RISK_VALUES.medium; break;
      case 'low': minRiskValue = RISK_VALUES.low; break;
      case 'all': minRiskValue = RISK_VALUES.info; break;
      default: minRiskValue = RISK_VALUES.medium;
    }
    
    // 遍历所有规则
    for (const [category, regex] of Object.entries(SENSITIVE_PATTERNS)) {
      const riskLevel = getRiskLevel(category);
      const riskValue = RISK_VALUES[riskLevel];
      
      // 根据告警等级过滤
      if (riskValue < minRiskValue) continue;
      
      // 测试匹配
      let match;
      while ((match = regex.exec(data)) !== null) {
        const value = match.length > 1 && match[1] ? match[1] : match[0];
        
        if (!results[category]) results[category] = [];
        if (!results[category].includes(value)) {
          results[category].push(value);
          hasSensitiveData = true;
          
          // 更新最高风险级别
          if (riskValue > RISK_VALUES[highestRiskLevel]) {
            highestRiskLevel = riskLevel;
          }
        }
        
        // 限制匹配数量
        if (results[category].length >= 3) break;
      }
    }
    
    return hasSensitiveData ? { results, highestRiskLevel } : null;
  }

  // 生成用户友好的风险描述
  function getRiskDescription(results) {
    const categories = Object.keys(results);
    const count = categories.length;
    
    if (count === 0) return '未知敏感信息';
    if (count === 1) return categories[0];
    if (count === 2) return `${categories[0]} 和 ${categories[1]}`;
    return `${categories[0]} 等 ${count} 类敏感信息`;
  }

  // ========== 监控输入框 ==========
  function scanInput(input) {
    const value = input.value;
    if (!value || value.length < 4) {
      // 移除视觉反馈
      input.style.outline = '';
      input.style.boxShadow = '';
      clearInputWarning(input);
      return null;
    }
    
    const scanResult = detectSensitiveData(value);
    if (scanResult) {
      // 添加视觉反馈
      const color = getRiskColor(Object.keys(scanResult.results)[0]);
      input.style.outline = `2px solid ${color}`;
      input.style.boxShadow = `0 0 5px ${color}`;
      
      // 显示提示
      showInputWarning(input, scanResult);
      
      return scanResult;
    } else {
      // 移除视觉反馈
      input.style.outline = '';
      input.style.boxShadow = '';
      clearInputWarning(input);
      return null;
    }
  }

  function clearInputWarning(input) {
    const warningId = `sensitive-warning-${input.id || input.name || 'input'}`;
    const existing = document.getElementById(warningId);
    if (existing) existing.remove();
  }

  function showInputWarning(input, scanResult) {
    clearInputWarning(input);
    
    const warningId = `sensitive-warning-${input.id || input.name || 'input'}`;
    const warning = document.createElement('div');
    warning.id = warningId;
    warning.style.cssText = `
      position: absolute;
      background: white;
      color: #333;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 12px;
      z-index: 10000;
      max-width: 300px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.15);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    const desc = getRiskDescription(scanResult.results);
    const categories = Object.keys(scanResult.results);
    const risksHtml = categories.map(category => {
      const color = getRiskColor(category);
      return `<span style="color: ${color}; font-weight: bold;">${category}</span>`;
    }).join(', ');
    
    // 获取告警级别说明
    const alertLevelText = {
      'high': '高风险',
      'medium': '中及以上风险',
      'low': '低及以上风险',
      'all': '所有信息'
    };
    
    warning.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
        <span style="background: ${getRiskColor(categories[0])}; color: white; width: 16px; height: 16px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold;">!</span>
        <strong>敏感信息检测（${alertLevelText[extensionSettings.alertLevel]}）</strong>
      </div>
      <div style="margin-left: 24px; font-size: 11px;">
        检测到: ${risksHtml}<br>
        <small>提交前请确认数据安全</small>
      </div>
    `;
    
    // 定位到输入框下方
    const rect = input.getBoundingClientRect();
    warning.style.top = `${rect.bottom + window.scrollY + 5}px`;
    warning.style.left = `${rect.left + window.scrollX}px`;
    
    document.body.appendChild(warning);
    
    // 自动消失
    setTimeout(() => {
      if (document.body.contains(warning)) {
        warning.remove();
      }
    }, WARNING_TIMEOUT);
  }

  // ========== 拦截表单提交 ==========
  function interceptFormSubmission(form) {
    if (form.dataset.sensitiveMonitored) return;
    form.dataset.sensitiveMonitored = 'true';
    
    form.addEventListener('submit', function(e) {
      let hasSensitiveData = false;
      const sensitiveFields = [];
      
      // 检查所有输入框
      const inputs = form.querySelectorAll('input, textarea, select');
      inputs.forEach(input => {
        const value = input.value;
        if (!value || value.length < 4) return;
        
        const scanResult = detectSensitiveData(value);
        if (scanResult) {
          hasSensitiveData = true;
          const categories = Object.keys(scanResult.results);
          sensitiveFields.push({
            name: input.name || input.id || '未命名字段',
            type: input.type || 'text',
            categories: categories,
            riskLevel: scanResult.highestRiskLevel
          });
        }
      });
      
      if (hasSensitiveData) {
        e.preventDefault();
        
        // 生成警告消息
        const fieldDesc = sensitiveFields.map(f => {
          const risks = f.categories.map(c => {
            const color = getRiskColor(c);
            return `<span style="color: ${color}; font-weight: bold;">${c}</span>`;
          }).join(', ');
          return `<strong>${f.name}</strong> (${f.type}) - 检测到: ${risks}`;
        }).join('<br><br>');
        
        // 根据最高风险级别确定对话框样式
        let highestRisk = 'info';
        sensitiveFields.forEach(f => {
          if (RISK_VALUES[f.riskLevel] > RISK_VALUES[highestRisk]) {
            highestRisk = f.riskLevel;
          }
        });
        
        // 创建自定义确认对话框
        showCustomConfirm(
          '敏感信息检测警告',
          `检测到表单包含敏感信息：<br><br>${fieldDesc}<br><br>当前告警级别: <strong>${getAlertLevelText(extensionSettings.alertLevel)}</strong><br>是否继续提交？`,
          () => {
            // 用户确认后移除监控再提交
            form.removeEventListener('submit', arguments.callee);
            form.submit();
          },
          () => {
            console.log('用户取消了表单提交');
          },
          highestRisk
        );
      }
    }, true); // 使用捕获阶段，确保最早拦截
  }

  function getAlertLevelText(level) {
    return {
      'high': '高风险',
      'medium': '中及以上风险',
      'low': '低及以上风险',
      'all': '所有信息'
    }[level] || '中及以上风险';
  }

  // 自定义确认对话框
  function showCustomConfirm(title, message, onConfirm, onCancel, riskLevel = 'medium') {
    // 移除现有对话框
    const existing = document.getElementById('custom-confirm-dialog');
    if (existing) existing.remove();
    
    // 创建遮罩层
    const overlay = document.createElement('div');
    overlay.id = 'custom-confirm-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.5);
      z-index: 20000;
      display: flex;
      align-items: center;
      justify-content: center;
    `;
    
    // 确定对话框颜色
    const borderColor = RISK_COLORS[riskLevel] || RISK_COLORS.medium;
    const buttonColor = riskLevel === 'high' ? '#e74c3c' : '#3498db';
    
    // 创建对话框
    const dialog = document.createElement('div');
    dialog.id = 'custom-confirm-dialog';
    dialog.style.cssText = `
      background: white;
      border-radius: 8px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
      padding: 20px;
      max-width: 450px;
      width: 90%;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      z-index: 20001;
      border-top: 3px solid ${borderColor};
    `;
    
    dialog.innerHTML = `
      <div style="margin-bottom: 15px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
          <span style="background: ${borderColor}; color: white; width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-weight: bold; flex-shrink: 0;">!</span>
          <h3 style="margin: 0; color: #333; font-size: 18px;">${title}</h3>
        </div>
        <div style="color: #555; line-height: 1.5; font-size: 14px;" id="confirm-message">
          ${message}
        </div>
      </div>
      <div style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 15px;">
        <button id="confirm-cancel" style="padding: 8px 16px; background: #e0e0e0; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; color: #333;">取消</button>
        <button id="confirm-ok" style="padding: 8px 16px; background: ${buttonColor}; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; color: white; font-weight: bold;">继续提交</button>
      </div>
      <div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid #eee; font-size: 12px; color: #7f8c8d;">
        <span style="background: ${borderColor}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-right: 5px;">${riskLevel.toUpperCase()}</span>
        此警告基于您设置的<strong>${getAlertLevelText(extensionSettings.alertLevel)}</strong>告警级别
      </div>
    `;
    
    // 添加到DOM
    document.body.appendChild(overlay);
    overlay.appendChild(dialog);
    
    // 防止滚动
    document.body.style.overflow = 'hidden';
    
    // 绑定事件
    document.getElementById('confirm-ok').addEventListener('click', function() {
      cleanup();
      onConfirm();
    });
    
    document.getElementById('confirm-cancel').addEventListener('click', function() {
      cleanup();
      onCancel();
    });
    
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) {
        cleanup();
        onCancel();
      }
    });
    
    // 按ESC键取消
    const keyHandler = function(e) {
      if (e.key === 'Escape') {
        cleanup();
        onCancel();
      }
    };
    
    document.addEventListener('keydown', keyHandler);
    
    function cleanup() {
      document.body.removeChild(overlay);
      document.body.style.overflow = '';
      document.removeEventListener('keydown', keyHandler);
    }
  }

  // ========== 初始化监控 ==========
  function initializeMonitoring() {
    // 获取设置
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ action: "getSettings" }, (response) => {
        if (response) {
          extensionSettings = response;
        }
        startMonitoring();
      });
    } else {
      startMonitoring();
    }
  }

  function startMonitoring() {
    // 监控现有输入框
    document.querySelectorAll('input, textarea').forEach(input => {
      setupInputMonitoring(input);
    });
    
    // 监控表单提交
    document.querySelectorAll('form').forEach(form => {
      interceptFormSubmission(form);
    });
    
    // 使用 MutationObserver 监控新元素
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === 1) { // 元素节点
              if (node.matches('input, textarea')) {
                setupInputMonitoring(node);
              } else if (node.matches('form')) {
                interceptFormSubmission(node);
              } else {
                // 检查子节点
                node.querySelectorAll('input, textarea').forEach(input => {
                  setupInputMonitoring(input);
                });
                node.querySelectorAll('form').forEach(form => {
                  interceptFormSubmission(form);
                });
              }
            }
          });
        }
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  function setupInputMonitoring(input) {
    if (observedInputs.has(input)) return;
    
    // 添加实时输入监控
    let timeout;
    input.addEventListener('input', () => {
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        // 限制扫描频率
        const now = Date.now();
        if (now - lastScanTime < SCAN_INTERVAL) return;
        lastScanTime = now;
        
        scanInput(input);
      }, 500);
    });
    
    // 添加聚焦监控
    input.addEventListener('focus', () => {
      scanInput(input);
    });
    
    // 失去焦点时检查
    input.addEventListener('blur', () => {
      scanInput(input);
    });
    
    observedInputs.set(input, true);
  }

  // ========== 启动 ==========
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeMonitoring);
  } else {
    initializeMonitoring();
  }

  console.log('敏感信息雷达：已激活智能输入框监控');
})();