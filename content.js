// content.js - 增强版敏感信息监控（支持Confluence富文本编辑器/iframe）
(function () {
  'use strict';

  // ========== 全局状态 ==========
  let extensionSettings = {
    enableAutoBlock: true,
    alertLevel: 'all', // 'high', 'medium', 'low', 'all'
    enableContext: true
  };
  const observedInputs = new WeakMap(); // 跟踪已监控的输入框
  const observedFrames = new WeakMap(); // 跟踪已监控的iframe
  let lastScanTime = 0;
  const SCAN_INTERVAL = 1000; // 1秒扫描间隔
  const WARNING_TIMEOUT = 5000; // 警告显示时间
  const CONFERENCE_EDITOR_SELECTOR = '#wysiwygTextarea_ifr'; // Confluence编辑器iframe

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

  // 风险级别到数值的映射
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

    if (typeof data !== 'string') {
      data = String(data);
    }

    // 确定最小风险级别
    let minRiskValue;
    switch (extensionSettings.alertLevel) {
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
      if (riskValue < minRiskValue) continue;

      let match;
      while ((match = regex.exec(data)) !== null) {
        const value = match.length > 1 && match[1] ? match[1] : match[0];
        if (!results[category]) results[category] = [];
        if (!results[category].includes(value)) {
          results[category].push(value);
          hasSensitiveData = true;
          if (riskValue > RISK_VALUES[highestRiskLevel]) {
            highestRiskLevel = riskLevel;
          }
        }
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

  // ========== 特定于Confluence的监控 ==========
  function monitorConfluenceEditor() {
    // 监控页面标题输入
    const titleInput = document.getElementById('content-title');
    if (titleInput && !observedInputs.has(titleInput)) {
      setupElementMonitoring(titleInput);
    }

    // 监控iframe编辑器
    const editorFrame = document.querySelector(CONFERENCE_EDITOR_SELECTOR);
    if (editorFrame && !observedFrames.has(editorFrame)) {
      monitorEditorFrame(editorFrame);
    }

    // 监控评论/发帖表单
    const saveButton = document.getElementById('rte-button-publish');
    if (saveButton) {
      setupFormInterception();
    }
  }

  function monitorEditorFrame(frame) {
    // 处理iframe加载
    function handleFrameLoad() {
      try {
        const frameDoc = frame.contentDocument || frame.contentWindow.document;
        if (!frameDoc) return;

        const editableElement = frameDoc.body;
        if (!editableElement || !editableElement.isContentEditable) return;

        // 监控富文本编辑器内容
        let lastContent = editableElement.innerHTML;
        
        function checkForChanges() {
          const currentContent = editableElement.innerHTML;
          if (currentContent !== lastContent) {
            lastContent = currentContent;
            scanConfluenceEditable(editableElement, frame);
          }
          setTimeout(checkForChanges, 500);
        }

        // 初始扫描
        scanConfluenceEditable(editableElement, frame);
        
        // 设置持续监控
        checkForChanges();
        
        // 交互事件监听
        editableElement.addEventListener('input', () => scanConfluenceEditable(editableElement, frame));
        editableElement.addEventListener('focus', () => scanConfluenceEditable(editableElement, frame));
        editableElement.addEventListener('blur', () => scanConfluenceEditable(editableElement, frame));
        editableElement.addEventListener('paste', () => setTimeout(() => scanConfluenceEditable(editableElement, frame), 100));
        
        observedFrames.set(frame, true);
        
      } catch (e) {
        console.warn('无法访问iframe内容:', e);
      }
    }

    // 等待iframe加载
    if (frame.contentDocument && frame.contentDocument.readyState === 'complete') {
      handleFrameLoad();
    } else {
      frame.addEventListener('load', handleFrameLoad);
    }
  }

  function scanConfluenceEditable(element, frame) {
    const content = element.innerHTML;
    const scanResult = detectSensitiveData(content);
    
    // 更新视觉反馈
    if (scanResult) {
      const color = getRiskColor(Object.keys(scanResult.results)[0]);
      frame.style.border = `2px solid ${color}`;
      showInputWarning(frame, scanResult, 'confluence-editor');
    } else {
      frame.style.border = '';
      clearInputWarning(frame, 'confluence-editor');
    }
    
    return scanResult;
  }

  function setupFormInterception() {
    const saveButton = document.getElementById('rte-button-publish');
    if (!saveButton || saveButton.dataset.monitored) return;
    
    saveButton.dataset.monitored = 'true';
    
    saveButton.addEventListener('click', function(e) {
      if (!extensionSettings.enableAutoBlock) return;
      
      const scanResults = [];
      
      // 1. 检查页面标题
      const titleInput = document.getElementById('content-title');
      if (titleInput && titleInput.value) {
        const titleResult = detectSensitiveData(titleInput.value);
        if (titleResult) {
          scanResults.push({
            element: titleInput,
            result: titleResult,
            field: '页面标题'
          });
        }
      }
      
      // 2. 检查编辑器内容
      const editorFrame = document.querySelector(CONFERENCE_EDITOR_SELECTOR);
      if (editorFrame) {
        try {
          const frameDoc = editorFrame.contentDocument || editorFrame.contentWindow.document;
          const editableElement = frameDoc.body;
          if (editableElement) {
            const contentResult = detectSensitiveData(editableElement.innerHTML);
            if (contentResult) {
              scanResults.push({
                element: editorFrame,
                result: contentResult,
                field: '页面内容'
              });
            }
          }
        } catch (err) {
          console.warn('无法检查编辑器内容:', err);
        }
      }
      
      // 3. 如果有敏感信息，阻止提交并显示警告
      if (scanResults.length > 0) {
        e.preventDefault();
        e.stopPropagation();
        
        // 收集最高风险级别
        let highestRisk = 'info';
        scanResults.forEach(item => {
          if (RISK_VALUES[item.result.highestRiskLevel] > RISK_VALUES[highestRisk]) {
            highestRisk = item.result.highestRiskLevel;
          }
        });
        
        // 生成显示内容
        const fieldDesc = scanResults.map(item => {
          const categories = Object.keys(item.result.results);
          const risks = categories.map(cat => {
            const color = getRiskColor(cat);
            return `<span style="color: ${color}; font-weight: bold;">${cat}</span>`;
          }).join(', ');
          return `<strong>${item.field}</strong> - 检测到: ${risks}`;
        }).join('<br><br>');
        
        showCustomConfirm(
          '敏感信息检测警告',
          `检测到表单包含敏感信息：<br><br>${fieldDesc}<br><br>当前告警级别: <strong>${getAlertLevelText(extensionSettings.alertLevel)}</strong><br>是否继续提交？`,
          () => {
            // 用户确认后，临时移除监听器并触发原始点击
            saveButton.removeEventListener('click', arguments.callee);
            saveButton.click();
          },
          () => {
            console.log('用户取消了表单提交');
          },
          highestRisk
        );
      }
    }, true); // 使用捕获阶段
  }

  // ========== 通用监控功能（增强版）==========
  function getUniqueElementId(el, prefix = '') {
    if (!el) return `element-${Date.now()}`;
    if (el.id) return `${prefix}${el.id}`;
    if (el.name) return `${prefix}${el.name}`;
    return `${prefix}elem-${Array.from(el.parentNode?.children || []).indexOf(el)}`;
  }

  function getValueFromElement(el) {
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      return el.value;
    } else if (el.hasAttribute('contenteditable') || el.isContentEditable) {
      return el.innerText || el.textContent || el.innerHTML || '';
    }
    return '';
  }

  function clearInputWarning(el, prefix = '') {
    const warningId = `sensitive-warning-${getUniqueElementId(el, prefix)}`;
    const existing = document.getElementById(warningId);
    if (existing) {
      existing.remove();
      return true;
    }
    return false;
  }

  function showInputWarning(el, scanResult, prefix = '') {
    clearInputWarning(el, prefix);
    const warningId = `sensitive-warning-${getUniqueElementId(el, prefix)}`;
    
    // 确保警告添加到正确的位置（处理iframe等情况）
    const container = el.tagName === 'IFRAME' ? 
      (el.parentNode || document.body) : 
      document.body;
    
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
      z-index: 2147483647; /* 最大z-index */
      max-width: 300px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.15);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      pointer-events: none;
    `;

    const desc = getRiskDescription(scanResult.results);
    const categories = Object.keys(scanResult.results);
    const risksHtml = categories.map(category => {
      const color = getRiskColor(category);
      return `<span style="color: ${color}; font-weight: bold;">${category}</span>`;
    }).join(', ');

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

    // 定位警告
    const rect = el.getBoundingClientRect();
    let top = rect.bottom + window.scrollY + 5;
    let left = rect.left + window.scrollX;
    
    // 防止警告超出视口
    if (top + 100 > window.innerHeight + window.scrollY) {
      top = rect.top + window.scrollY - 60;
    }
    if (left + 300 > window.innerWidth + window.scrollX) {
      left = window.innerWidth + window.scrollX - 320;
    }

    warning.style.top = `${top}px`;
    warning.style.left = `${left}px`;
    
    container.appendChild(warning);

    // 自动消失
    setTimeout(() => {
      if (container.contains(warning)) {
        warning.remove();
      }
    }, WARNING_TIMEOUT);
  }

  // 自定义确认对话框
  function showCustomConfirm(title, message, onConfirm, onCancel, riskLevel = 'medium') {
    const existing = document.getElementById('custom-confirm-dialog');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'custom-confirm-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.5);
      z-index: 2147483646; /* 低于警告，高于一切 */
      display: flex;
      align-items: center;
      justify-content: center;
    `;

    const borderColor = RISK_COLORS[riskLevel] || RISK_COLORS.medium;
    const buttonColor = riskLevel === 'high' ? '#e74c3c' : '#3498db';

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
      z-index: 2147483647;
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

    document.body.appendChild(overlay);
    overlay.appendChild(dialog);
    document.body.style.overflow = 'hidden';

    document.getElementById('confirm-ok').addEventListener('click', function () {
      cleanup();
      onConfirm();
    });
    document.getElementById('confirm-cancel').addEventListener('click', function () {
      cleanup();
      onCancel();
    });
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) {
        cleanup();
        onCancel();
      }
    });

    const keyHandler = function (e) {
      if (e.key === 'Escape') {
        cleanup();
        onCancel();
      }
    };
    document.addEventListener('keydown', keyHandler);

    function cleanup() {
      if (document.body.contains(overlay)) {
        document.body.removeChild(overlay);
      }
      document.body.style.overflow = '';
      document.removeEventListener('keydown', keyHandler);
    }
  }

  function getAlertLevelText(level) {
    return {
      'high': '高风险',
      'medium': '中及以上风险',
      'low': '低及以上风险',
      'all': '所有信息'
    }[level] || '中及以上风险';
  }

  // ========== 通用输入监控（增强版）==========
  function setupElementMonitoring(el) {
    if (observedInputs.has(el)) return;

    let isTextareaOrInput = el.tagName === 'TEXTAREA' || el.tagName === 'INPUT';
    let isContentEditable = el.hasAttribute('contenteditable') || el.isContentEditable;

    if (!isTextareaOrInput && !isContentEditable) return;

    // 聚焦/失焦检测
    el.addEventListener('focus', () => scanElement(el));
    el.addEventListener('blur', () => scanElement(el));

    // 输入监控
    let timeout;
    const onInput = () => {
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        const now = Date.now();
        if (now - lastScanTime < SCAN_INTERVAL) return;
        lastScanTime = now;
        scanElement(el);
      }, 500);
    };

    if (isTextareaOrInput) {
      el.addEventListener('input', onInput);
    } else if (isContentEditable) {
      el.addEventListener('keyup', onInput);
      el.addEventListener('paste', onInput);
      el.addEventListener('cut', onInput);
    }

    observedInputs.set(el, true);
    
    // 初始扫描
    setTimeout(() => scanElement(el), 100);
  }

  function scanElement(el) {
    const value = getValueFromElement(el);
    if (!value || value.length < 4) {
      el.style.outline = '';
      el.style.boxShadow = '';
      clearInputWarning(el);
      return null;
    }

    const scanResult = detectSensitiveData(value);
    if (scanResult) {
      const color = getRiskColor(Object.keys(scanResult.results)[0]);
      el.style.outline = `2px solid ${color}`;
      el.style.boxShadow = `0 0 5px ${color}`;
      showInputWarning(el, scanResult);
      return scanResult;
    } else {
      el.style.outline = '';
      el.style.boxShadow = '';
      clearInputWarning(el);
      return null;
    }
  }

  // ========== 初始化监控 ==========
  function initializeMonitoring() {
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
    // 监控标准输入元素
    document.querySelectorAll('input, textarea, [contenteditable="true"]').forEach(setupElementMonitoring);
    
    // 处理Confluence编辑器特殊情况
    if (document.querySelector(CONFERENCE_EDITOR_SELECTOR) || 
        document.getElementById('content-title') || 
        document.getElementById('rte-button-publish')) {
      monitorConfluenceEditor();
    }
    
    // 监控表单
    document.querySelectorAll('form').forEach(form => {
      if (!form.dataset.sensitiveMonitored) {
        form.dataset.sensitiveMonitored = 'true';
        form.addEventListener('submit', handleFormSubmit, true);
      }
    });

    // MutationObserver 监控动态内容
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === 1) {
              // 检查是否是Confluence编辑器相关元素
              if (node.querySelector(CONFERENCE_EDITOR_SELECTOR) || 
                  node.id === 'content-title' || 
                  node.id === 'rte-button-publish') {
                setTimeout(monitorConfluenceEditor, 100);
              }
              
              // 标准元素监控
              if (node.matches('input, textarea, [contenteditable="true"]')) {
                setupElementMonitoring(node);
              } else if (node.matches('form')) {
                if (!node.dataset.sensitiveMonitored) {
                  node.dataset.sensitiveMonitored = 'true';
                  node.addEventListener('submit', handleFormSubmit, true);
                }
              } else {
                node.querySelectorAll('input, textarea, [contenteditable="true"]').forEach(setupElementMonitoring);
                node.querySelectorAll('form').forEach(form => {
                  if (!form.dataset.sensitiveMonitored) {
                    form.dataset.sensitiveMonitored = 'true';
                    form.addEventListener('submit', handleFormSubmit, true);
                  }
                });
              }
            }
          });
        }
      });
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }
  
  function handleFormSubmit(e) {
    if (!extensionSettings.enableAutoBlock) return;
    
    let hasSensitiveData = false;
    const sensitiveFields = [];
    
    const formData = new FormData(this);
    for (const [name, value] of formData.entries()) {
      if (typeof value === 'string' && value.length > 3) {
        const scanResult = detectSensitiveData(value);
        if (scanResult) {
          hasSensitiveData = true;
          const categories = Object.keys(scanResult.results);
          sensitiveFields.push({
            name: name,
            value: value.substring(0, 50) + (value.length > 50 ? '...' : ''),
            categories: categories,
            riskLevel: scanResult.highestRiskLevel
          });
        }
      }
    }
    
    // 检查富文本编辑器（在iframe中）
    const editorFrame = document.querySelector(CONFERENCE_EDITOR_SELECTOR);
    if (editorFrame) {
      try {
        const frameDoc = editorFrame.contentDocument || editorFrame.contentWindow.document;
        const editableElement = frameDoc.body;
        if (editableElement) {
          const contentResult = detectSensitiveData(editableElement.innerHTML);
          if (contentResult) {
            hasSensitiveData = true;
            const categories = Object.keys(contentResult.results);
            sensitiveFields.push({
              name: '富文本内容',
              value: editableElement.textContent.substring(0, 50) + '...',
              categories: categories,
              riskLevel: contentResult.highestRiskLevel
            });
          }
        }
      } catch (err) {
        console.warn('无法检查iframe内容:', err);
      }
    }
    
    if (hasSensitiveData) {
      e.preventDefault();
      
      // 计算最高风险级别
      let highestRisk = 'info';
      sensitiveFields.forEach(f => {
        if (RISK_VALUES[f.riskLevel] > RISK_VALUES[highestRisk]) {
          highestRisk = f.riskLevel;
        }
      });
      
      const fieldDesc = sensitiveFields.map(f => {
        const risks = f.categories.map(c => {
          const color = getRiskColor(c);
          return `<span style="color: ${color}; font-weight: bold;">${c}</span>`;
        }).join(', ');
        return `<strong>${f.name}</strong>: "${f.value}" - 检测到: ${risks}`;
      }).join('<br><br>');
      
      showCustomConfirm(
        '敏感信息检测警告',
        `检测到表单包含敏感信息：<br><br>${fieldDesc}<br><br>当前告警级别: <strong>${getAlertLevelText(extensionSettings.alertLevel)}</strong><br>是否继续提交？`,
        () => {
          // 用户确认后，移除监听器并提交
          this.removeEventListener('submit', handleFormSubmit, true);
          this.submit();
        },
        () => {
          console.log('用户取消了表单提交');
        },
        highestRisk
      );
    }
  }

  // ========== 启动 ==========
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeMonitoring);
  } else {
    initializeMonitoring();
  }

  console.log('敏感信息雷达：已激活评论区/发帖区增强监控');
})();