document.addEventListener('DOMContentLoaded', () => {
  const resultDiv = document.getElementById('result');
  const loader = document.querySelector('.loader');
  const loadingText = document.getElementById('loading-text');
  const notificationContainer = document.getElementById('notification-container');
  const currentAlertLevelEl = document.getElementById('currentAlertLevel');

  // 默认设置
  let settings = {
    enableAutoBlock: true,
    alertLevel: 'all', // 'high', 'medium', 'low', 'all'
    enableContext: true,
    domainMode: 'include',
    includeDomains: ['wiki.icbc'],
    excludeDomains: ['example.com', 'test.com']
  };

  // 加载已保存的设置
  chrome.storage.sync.get(settings, (savedSettings) => {
    settings = { ...settings, ...savedSettings };
    document.getElementById('enableAutoBlock').checked = settings.enableAutoBlock;
    document.getElementById('enableContext').checked = settings.enableContext;
    document.getElementById('domainMode').value = settings.domainMode;

    // 更新域名列表UI
    renderDomainList();

    // 更新告警级别UI
    updateAlertLevelUI(settings.alertLevel);
  });

  // 显示加载状态
  function showLoader(message = '正在分析中...') {
    loadingText.textContent = message;
    loader.style.display = 'block';
  }

  // 隐藏加载状态
  function hideLoader() {
    loader.style.display = 'none';
  }

  // 显示通知
  function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notificationContainer.innerHTML = '';
    notificationContainer.appendChild(notification);
    setTimeout(() => {
      if (notificationContainer.contains(notification)) {
        notificationContainer.removeChild(notification);
      }
    }, 5000);
  }

  // 检查当前标签是否是普通网页
  function checkValidTab(callback) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://') || tab.url.startsWith('about:')) {
        showNotification('只能在普通网页上使用此功能', 'warning');
        hideLoader();
        return;
      }
      callback(tab);
    });
  }

  // 显示检测结果
  function displayResults(results, type = 'page') {
    resultDiv.innerHTML = '';
    if (!results || Object.keys(results).length === 0) {
      resultDiv.innerHTML = `<p class="notification success">未检测到敏感信息 ✅</p>`;
      return;
    }

    // 统计风险级别
    let highRiskCount = 0, mediumRiskCount = 0, lowRiskCount = 0, infoCount = 0;

    // 按风险级别分组
    const riskGroups = {
      high: [],
      medium: [],
      low: [],
      info: []
    };

    Object.entries(results).forEach(([category, matches]) => {
      // 跳过空结果
      if (!matches || matches.length === 0) return;

      // 根据分类确定风险级别
      const riskLevel = getRiskLevel(category);

      // 统计
      switch(riskLevel) {
        case 'high': highRiskCount += matches.length; break;
        case 'medium': mediumRiskCount += matches.length; break;
        case 'low': lowRiskCount += matches.length; break;
        case 'info': infoCount += matches.length; break;
      }

      // 添加到对应风险组
      riskGroups[riskLevel].push({ category, matches });
    });

    // 添加风险统计
    const statsDiv = document.createElement('div');
    statsDiv.className = 'stats';
    statsDiv.innerHTML = `
      <span>🔴 高风险: ${highRiskCount}</span>
      <span>🟠 中风险: ${mediumRiskCount}</span>
      <span>🟢 低风险: ${lowRiskCount}</span>
      <span>🔵 信息: ${infoCount}</span>
    `;
    resultDiv.appendChild(statsDiv);

    // 按风险级别顺序显示结果
    ['high', 'medium', 'low', 'info'].forEach(riskLevel => {
      if (riskGroups[riskLevel].length > 0) {
        riskGroups[riskLevel].forEach(group => {
          const { category, matches } = group;
          const categoryDiv = document.createElement('div');
          categoryDiv.className = 'findings-container';
          categoryDiv.style.borderLeftColor = getRiskColor(category);

          const riskClass = riskLevel === 'high' ? 'risk-high' :
                            riskLevel === 'medium' ? 'risk-medium' :
                            riskLevel === 'low' ? 'risk-low' : 'risk-info';
          const riskBadgeClass = riskLevel === 'high' ? 'high' :
                                riskLevel === 'medium' ? 'medium' :
                                riskLevel === 'low' ? 'low' : 'info';

          categoryDiv.innerHTML = `<div><span class="${riskClass}">${category}</span><span class="risk-badge ${riskBadgeClass}">${riskLevel}</span></div>`;

          matches.forEach(match => {
            const matchDiv = document.createElement('div');
            matchDiv.className = 'match-item';
            let matchContent = `<span class="${riskClass}">${escapeHtml(match.value)}</span>`;

            // 添加上下文
            if (settings.enableContext && match.context) {
              const startIdx = Math.max(0, match.index - 30);
              const endIdx = Math.min(match.context.length, match.index + match.value.length + 30);
              const highlightStart = match.index - startIdx;
              const highlightEnd = highlightStart + match.value.length;
              let contextText = escapeHtml(match.context.substring(startIdx, endIdx));
              contextText = contextText.substring(0, highlightStart) +
                `<span class="${riskClass}">${contextText.substring(highlightStart, highlightEnd)}</span>` +
                contextText.substring(highlightEnd);
              matchContent += `<div class="match-context">${contextText}</div>`;
            }

            // 添加复制按钮
            matchContent += `<button class="copy-btn" data-value="${escapeHtml(match.value)}">复制</button>`;
            matchDiv.innerHTML = matchContent;
            categoryDiv.appendChild(matchDiv);
          });
          resultDiv.appendChild(categoryDiv);
        });
      }
    });

    // 添加复制功能
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const value = e.target.getAttribute('data-value');
        navigator.clipboard.writeText(value).then(() => {
          const originalText = e.target.textContent;
          e.target.textContent = '已复制!';
          setTimeout(() => {
            e.target.textContent = originalText;
          }, 1000);
        });
      });
    });

    // 显示警告
    if (highRiskCount > 0) {
      showNotification(`检测到 ${highRiskCount} 个高风险敏感信息！建议谨慎处理此页面。`, 'error');
    } else if (mediumRiskCount > 0) {
      showNotification(`检测到 ${mediumRiskCount} 个中风险敏感信息，请注意数据安全。`, 'warning');
    }
  }

  // HTML转义
  function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[&<>"']/g, m =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])
    );
  }

  // 获取风险级别
  function getRiskLevel(category) {
    const highRiskCategories = [
      'API Key', 'Secret', '阿里云AK', '腾讯云AK', '百度云AK', '京东云', '火山引擎',
      'Shiro特征', '数据库连接', '身份证', 'JWT Token', 'AWS Key', 'Google API',
      'GitHub Token', 'RSA私钥', 'SSH私钥', 'PEM私钥', 'flag!!!', 'ak sk', '云安全'
    ];
    const mediumRiskCategories = [
      '明文ID参数', 'JSON-ID参数', '密码字段', '内网IP', '敏感管理路径'
    ];
    const lowRiskCategories = [
      'Swagger UI', 'URL跳转参数', '账号字段', '加密算法', '车牌号'
    ];

    if (highRiskCategories.includes(category)) return 'high';
    if (mediumRiskCategories.includes(category)) return 'medium';
    if (lowRiskCategories.includes(category)) return 'low';
    return 'info';
  }

  // 获取风险颜色
  function getRiskColor(category) {
    const riskLevel = getRiskLevel(category);
    return riskLevel === 'high' ? '#e74c3c' :
           riskLevel === 'medium' ? '#e67e22' :
           riskLevel === 'low' ? '#2ecc71' : '#3498db';
  }

  // 更新告警级别UI
  function updateAlertLevelUI(level) {
    // 更新按钮选择状态
    document.querySelectorAll('.alert-level-option').forEach(btn => {
      btn.classList.toggle('selected', btn.dataset.level === level);
    });

    // 更新描述
    document.querySelector('.high-desc').style.display = level === 'high' ? 'inline' : 'none';
    document.querySelector('.medium-desc').style.display = level === 'medium' ? 'inline' : 'none';
    document.querySelector('.low-desc').style.display = level === 'low' ? 'inline' : 'none';
    document.querySelector('.all-desc').style.display = level === 'all' ? 'inline' : 'none';

    // 更新标题显示
    const levelText = {
      'high': '高风险',
      'medium': '中及以上风险',
      'low': '低及以上风险',
      'all': '所有信息'
    };
    const levelClasses = {
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'all': 'all'
    };
    currentAlertLevelEl.textContent = levelText[level] || '中及以上风险';
    currentAlertLevelEl.className = `current-alert-level ${levelClasses[level] || 'medium'}`;
  }

  // ========== 共享分析逻辑（与 content.js 一致） ==========
  function getRiskLevelForAnalysis(category) {
    const highRiskCategories = [
      'API Key', 'Secret', '阿里云AK', '腾讯云AK', '百度云AK', '京东云', '火山引擎',
      'Shiro特征', '数据库连接', '身份证', 'JWT Token', 'AWS Key', 'Google API',
      'GitHub Token', 'RSA私钥', 'SSH私钥', 'PEM私钥', 'flag!!!', 'ak sk', '云安全'
    ];
    const mediumRiskCategories = [
      '明文ID参数', 'JSON-ID参数', '密码字段', '内网IP', '敏感管理路径'
    ];
    const lowRiskCategories = [
      'Swagger UI', 'URL跳转参数', '账号字段', '加密算法', '车牌号'
    ];

    if (highRiskCategories.includes(category)) return 'high';
    if (mediumRiskCategories.includes(category)) return 'medium';
    if (lowRiskCategories.includes(category)) return 'low';
    return 'info';
  }

  function analyzeContent(content, settings) {
    const patterns = {
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

    const results = {};
    const RISK_VALUES = {
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };

    // 确定最小风险级别
    let minRiskValue;
    switch(settings.alertLevel) {
      case 'high': minRiskValue = RISK_VALUES.high; break;
      case 'medium': minRiskValue = RISK_VALUES.medium; break;
      case 'low': minRiskValue = RISK_VALUES.low; break;
      case 'all': minRiskValue = RISK_VALUES.info; break;
      default: minRiskValue = RISK_VALUES.medium;
    }

    Object.entries(patterns).forEach(([category, pattern]) => {
      const riskLevel = getRiskLevelForAnalysis(category);
      const riskValue = RISK_VALUES[riskLevel];

      // 根据告警级别过滤
      if (riskValue < minRiskValue) return;

      const matches = [];
      let match;
      while ((match = pattern.exec(content)) !== null) {
        if (matches.length >= 10) break;

        let fullMatch = match[0];
        if (match.length > 1 && match[1]) fullMatch = match[1];

        let context = '';
        if (settings.enableContext) {
          const startIdx = Math.max(0, match.index - 100);
          const endIdx = Math.min(content.length, match.index + match[0].length + 100);
          context = content.substring(startIdx, endIdx);
        }

        if (!matches.some(m => m.value === fullMatch)) {
          matches.push({
            value: fullMatch,
            context: context,
            index: match.index - Math.max(0, match.index - 100)
          });
        }
      }

      if (matches.length > 0) results[category] = matches;
    });

    return results;
  }

  // ========== 页面检测（修复版） ==========
  document.getElementById('extract').addEventListener('click', () => {
    showLoader('正在分析页面内容...');
    checkValidTab((tab) => {
      // 注入脚本获取页面内容并分析
      chrome.scripting.executeScript(
        {
          target: { tabId: tab.id },
          func: () => {
            // 获取完整页面内容
            return document.documentElement.outerHTML;
          }
        },
        (injectionResults) => {
          if (chrome.runtime.lastError) {
            hideLoader();
            showNotification(`执行错误: ${chrome.runtime.lastError.message}`, 'error');
            return;
          }

          if (!injectionResults || !injectionResults[0] || !injectionResults[0].result) {
            hideLoader();
            resultDiv.innerHTML = '<p class="notification warning">未能获取页面内容</p>';
            return;
          }

          const pageContent = injectionResults[0].result;
          const results = analyzeContent(pageContent, settings);
          hideLoader();
          displayResults(results, 'page');
        }
      );
    });
  });

  // ========== 深度扫描JS文件 ==========
  document.getElementById('deepScan').addEventListener('click', () => {
    showLoader('正在扫描JS文件...');
    checkValidTab((tab) => {
      // 获取所有JS文件URL
      chrome.scripting.executeScript(
        {
          target: { tabId: tab.id },
          func: () => {
            const scripts = Array.from(document.querySelectorAll('script[src]'));
            return [...new Set(scripts.map(script => script.src))].filter(url => url && url.startsWith('http'));
          }
        },
        (injectionResults) => {
          if (chrome.runtime.lastError) {
            hideLoader();
            showNotification(`执行错误: ${chrome.runtime.lastError.message}`, 'error');
            return;
          }

          if (!injectionResults || !injectionResults[0] || !injectionResults[0].result) {
            hideLoader();
            resultDiv.innerHTML = '<p class="notification warning">未能获取JS文件列表</p>';
            return;
          }

          const jsFiles = injectionResults[0].result;
          if (jsFiles.length === 0) {
            hideLoader();
            resultDiv.innerHTML = '<p class="notification success">未找到JS文件</p>';
            return;
          }

          showLoader(`正在分析 ${jsFiles.length} 个JS文件...`);
          let completed = 0;
          const allResults = {};

          // 分析每个JS文件
          jsFiles.forEach(url => {
            fetch(url)
              .then(response => {
                if (!response.ok) throw new Error('Network response was not ok');
                return response.text();
              })
              .then(content => {
                const results = analyzeContent(content, settings);
                if (Object.keys(results).length > 0) {
                  allResults[url] = results;
                }
              })
              .catch(error => {
                console.error(`无法分析JS文件 ${url}:`, error);
              })
              .finally(() => {
                completed++;
                loadingText.textContent = `已分析 ${completed}/${jsFiles.length} 个文件`;
                if (completed === jsFiles.length) {
                  hideLoader();
                  displayDeepScanResults(allResults);
                }
              });
          });
        }
      );
    });
  });

  // 显示深度扫描结果
  function displayDeepScanResults(allResults) {
    resultDiv.innerHTML = '';
    if (Object.keys(allResults).length === 0) {
      resultDiv.innerHTML = `<p class="notification success">未在JS文件中检测到敏感信息 ✅</p>`;
      return;
    }

    let totalFindings = 0;
    Object.entries(allResults).forEach(([url, results]) => {
      const fileDiv = document.createElement('div');
      fileDiv.className = 'js-file';

      // 统计此文件中的发现
      let fileFindings = 0;
      Object.values(results).forEach(matches => {
        fileFindings += matches ? matches.length : 0;
      });
      totalFindings += fileFindings;

      const fileName = url.split('/').pop() || url;
      fileDiv.innerHTML = `
        <div class="file-header">
          <span title="${escapeHtml(url)}" class="truncated">${escapeHtml(fileName)}</span>
          <span class="risk-badge ${fileFindings > 5 ? 'high' : fileFindings > 2 ? 'medium' : 'low'}">
            ${fileFindings} 项发现
          </span>
        </div>
      `;

      // 分析结果
      const tempDiv = document.createElement('div');
      displayResults(results, 'jsfile');
      tempDiv.appendChild(resultDiv.cloneNode(true));
      fileDiv.appendChild(tempDiv.firstChild);
      resultDiv.appendChild(fileDiv);
    });

    // 添加总计
    if (totalFindings > 0) {
      showNotification(`在JS文件中总共检测到 ${totalFindings} 个敏感信息`,
        totalFindings > 10 ? 'error' : totalFindings > 5 ? 'warning' : 'info');
    }
  }

  // ========== 域名管理功能 ==========
  // 渲染域名列表
  function renderDomainList() {
    const container = document.getElementById('domainListContainer');
    container.innerHTML = '';

    const domains = settings.domainMode === 'include' ? 
      settings.includeDomains : settings.excludeDomains;

    if (domains.length === 0) {
      container.innerHTML = '<p style="color: #6c757d; text-align: center;">暂无域名</p>';
      return;
    }

    domains.forEach((domain, index) => {
      const domainItem = document.createElement('div');
      domainItem.style.display = 'flex';
      domainItem.style.alignItems = 'center';
      domainItem.style.padding = '5px 0';
      domainItem.style.borderBottom = '1px solid #eee';

      domainItem.innerHTML = `
        <span style="flex: 1; padding-left: 5px;">${escapeHtml(domain)}</span>
        <button class="remove-domain" data-index="${index}" style="background: #e74c3c; color: white; border: none; border-radius: 3px; padding: 2px 6px; font-size: 11px; cursor: pointer;">移除</button>
      `;

      container.appendChild(domainItem);
    });

    // 添加移除按钮事件
    document.querySelectorAll('.remove-domain').forEach(btn => {
      btn.addEventListener('click', function() {
        const index = parseInt(this.getAttribute('data-index'));
        if (settings.domainMode === 'include') {
          settings.includeDomains.splice(index, 1);
        } else {
          settings.excludeDomains.splice(index, 1);
        }
        renderDomainList();
      });
    });
  }

  // 添加新域名
  document.getElementById('addDomain').addEventListener('click', function() {
    const domainMode = document.getElementById('domainMode').value;
    const domains = domainMode === 'include' ? 
      settings.includeDomains : settings.excludeDomains;

    // 使用prompt简单实现，实际应用中可以用更好的输入方式
    const newDomain = prompt('请输入域名(例如: wiki.icbc.com 或 *.icbc.com):');
    if (newDomain && newDomain.trim() !== '') {
      const cleanDomain = newDomain.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/^\*\.?/, '');

      if (!domains.includes(cleanDomain) && cleanDomain !== '') {
        domains.push(cleanDomain);
        renderDomainList();
      } else if (cleanDomain !== '') {
        showNotification('该域名已存在', 'warning');
      }
    }
  });

  // 切换域名模式
  document.getElementById('domainMode').addEventListener('change', function() {
    settings.domainMode = this.value;
    renderDomainList();
  });

  // 切换设置面板
  document.getElementById('toggleSettings').addEventListener('click', (e) => {
    e.preventDefault();
    const settingsPanel = document.getElementById('settingsPanel');
    const toggleBtn = e.target;
    if (settingsPanel.style.display === 'none' || settingsPanel.style.display === '') {
      settingsPanel.style.display = 'block';
      toggleBtn.textContent = '隐藏设置 ▲';
    } else {
      settingsPanel.style.display = 'none';
      toggleBtn.textContent = '高级设置 ▼';
    }
  });

  // 告警级别选择
  document.querySelectorAll('.alert-level-option').forEach(option => {
    option.addEventListener('click', function() {
      document.querySelectorAll('.alert-level-option').forEach(btn => {
        btn.classList.remove('selected');
      });
      this.classList.add('selected');
      settings.alertLevel = this.dataset.level;
      // 更新描述
      document.querySelector('.high-desc').style.display = settings.alertLevel === 'high' ? 'inline' : 'none';
      document.querySelector('.medium-desc').style.display = settings.alertLevel === 'medium' ? 'inline' : 'none';
      document.querySelector('.low-desc').style.display = settings.alertLevel === 'low' ? 'inline' : 'none';
      document.querySelector('.all-desc').style.display = settings.alertLevel === 'all' ? 'inline' : 'none';
    });
  });

  // 保存设置
  document.getElementById('saveSettings').addEventListener('click', () => {
    settings.enableAutoBlock = document.getElementById('enableAutoBlock').checked;
    settings.enableContext = document.getElementById('enableContext').checked;
    settings.domainMode = document.getElementById('domainMode').value;

    chrome.storage.sync.set(settings, () => {
      // 通知内容脚本更新设置
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { action: "updateSettings", settings: settings });
          chrome.tabs.sendMessage(tabs[0].id, { 
            action: "updateDomainSettings",
            domainMode: settings.domainMode,
            includeDomains: settings.includeDomains,
            excludeDomains: settings.excludeDomains
          });
        }
      });

      // 更新标题显示
      updateAlertLevelUI(settings.alertLevel);
      showNotification('设置已保存', 'success');
    });
  });
});
