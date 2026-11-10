'use strict';
'require view';
'require rpc';

function display(value) {
	if (value === null || value === undefined || value === '')
		return '-';
	return String(value);
}

const PROTOCOL_LABELS = {
	'onvif-wsdiscovery': 'ONVIF',
	'uniview-wsdiscovery': 'UNV',
	'hikvision-sadp': 'SADP',
	'dahua-dvrip': 'DVRIP',
	'dahua-dhip': 'DHIP',
	'arp': 'ARP',
	'dhcp': 'DHCP'
};

function protocolLabels(value) {
	if (!Array.isArray(value) || !value.length)
		return '-';
	return value.map(function(protocol) {
		return PROTOCOL_LABELS[protocol] || protocol;
	}).join(', ');
}

/* Camera metadata is unauthenticated network input. Always render it as a
 * Text node rather than allowing LuCI's DOM helper to interpret it as HTML. */
function text(value) {
	return document.createTextNode(display(value));
}

function deviceLabel(device) {
	return device.model || '-';
}

function serviceLabel(device) {
	if (device.web_url)
		return device.web_url;
	if (device.command_port)
		return 'command:' + device.command_port;
	return '-';
}

function ageLabel(ageMs) {
	const seconds = Math.max(0, Math.floor(Number(ageMs || 0) / 1000));
	return _('%d 秒前').format(seconds);
}

function lastSeenTimestamp(device) {
	const timestamp = Number(device && device.last_seen_ms);
	return Number.isFinite(timestamp) && timestamp > 0 ? timestamp : 0;
}

function lastSeenLabel(device) {
	if (!lastSeenTimestamp(device))
		return '-';
	return ageLabel(device.age_ms);
}

function ipSortValue(value) {
	const textValue = String(value || '');
	const octets = textValue.split('.');
	if (octets.length === 4 && octets.every(function(octet) {
		return /^\d{1,3}$/.test(octet) && Number(octet) <= 255;
	})) {
		return {
			valid: true,
			value: octets.reduce(function(total, octet) {
				return total * 256 + Number(octet);
			}, 0),
			text: textValue
		};
	}
	return { valid: false, value: 0, text: textValue };
}

function sortDevices(devices) {
	return devices.slice().sort(function(left, right) {
		const leftIp = ipSortValue(left.ip);
		const rightIp = ipSortValue(right.ip);
		if (leftIp.valid !== rightIp.valid)
			return leftIp.valid ? -1 : 1;
		if (leftIp.valid)
			return leftIp.value - rightIp.value;
		return leftIp.text < rightIp.text ? -1 : leftIp.text > rightIp.text ? 1 : 0;
	});
}

function classificationLabel(device) {
	if (device.classification === 'camera')
		return _('协议确认');
	return _('二层候选');
}

function presenceLabel(device) {
	return device.presence === 'online' ? _('在线') : _('最近出现');
}

function parseReply(reply) {
	let result;
	try {
		result = JSON.parse((reply && reply.stdout) || '{}');
	}
	catch (error) {
		result = {
			ok: false,
			error: _('扫描器返回了无效 JSON：%s').format(error.message || error),
			warnings: [],
			devices: [],
			count: 0
		};
	}

	if (reply && reply.stderr && !result.error)
		result.error = reply.stderr;
	if (reply && reply.code && !result.error)
		result.error = _('扫描器退出状态：%s').format(reply.code);
	return result;
}

function replaceContent(container, nodes) {
	while (container.firstChild)
		container.removeChild(container.firstChild);
	(Array.isArray(nodes) ? nodes : [ nodes ]).forEach(function(node) {
		container.appendChild(node);
	});
}

function renderWarnings(warnings) {
	if (!Array.isArray(warnings) || !warnings.length)
		return E('div', { 'style': 'display: none' });

	return E('div', { 'class': 'alert-message warning' }, [
		E('strong', {}, [ _('警告') + '：' ]),
		E('ul', {}, warnings.map(function(message) {
			return E('li', {}, [ text(message) ]);
		}))
	]);
}

function renderTable(devices) {
	if (!Array.isArray(devices) || !devices.length)
		return E('div', { 'class': 'alert-message notice' }, [
			_('当前没有缓存的发现响应或 ARP/DHCP 观察结果。请检查接口、VLAN、防火墙 input 策略和二层连通性。')
		]);

	/* IP address is the only ordering criterion. */
	const sortedDevices = sortDevices(devices);

	const sourceHelp = E('p', { 'class': 'cbi-map-descr' }, [
		_('发现来源简写：ONVIF=标准 WS-Discovery，UNV=宇视 WS-Discovery，SADP=海康，DVRIP/DHIP=大华，ARP/DHCP=二层观察。协议确认的 IPC 优先显示；仅有 ARP/DHCP 的设备只是二层候选。')
	]);

	const table = E('table', { 'class': 'table cbi-section-table' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, [ _('IP 地址') ]),
			E('th', { 'class': 'th' }, [ _('MAC 地址') ]),
			E('th', { 'class': 'th' }, [ _('状态') ]),
			/* 分类由排序和上方说明体现，保留代码便于后续恢复。
			E('th', { 'class': 'th' }, [ _('分类') ]),
			*/
			E('th', { 'class': 'th' }, [ _('最后发现') ]),
			E('th', { 'class': 'th' }, [ _('发现来源') ]),
			E('th', { 'class': 'th' }, [ _('制造商') ]),
			E('th', { 'class': 'th' }, [ _('型号') ]),
			E('th', { 'class': 'th' }, [ _('序列号') ])
			/* 以下详情列按现场要求暂时隐藏，保留代码便于后续恢复。
			, E('th', { 'class': 'th' }, [ _('OUI 厂商') ])
			, E('th', { 'class': 'th' }, [ _('固件') ])
			, E('th', { 'class': 'th' }, [ _('服务地址') ])
			*/
		])
	]);

	sortedDevices.forEach(function(device) {
		/* 服务链接生成逻辑随详情列一起隐藏。
		const service = serviceLabel(device);
		const serviceNode = /^https?:\/\//.test(service)
			? E('a', { 'href': service, 'target': '_blank', 'rel': 'noreferrer noopener' }, [ text(service) ])
			: text(service);
		*/

			table.appendChild(E('tr', { 'class': 'tr cbi-section-table-row' }, [
			E('td', { 'class': 'td' }, [ text(device.ip) ]),
			E('td', { 'class': 'td', 'style': 'font-family: monospace' }, [ text(device.mac) ]),
			E('td', { 'class': 'td' }, [ text(presenceLabel(device)) ]),
			/* 分类由排序和上方说明体现，保留代码便于后续恢复。
			E('td', { 'class': 'td' }, [ text(classificationLabel(device)) ]),
			*/
			E('td', { 'class': 'td' }, [ text(lastSeenLabel(device)) ]),
			E('td', { 'class': 'td' }, [ text(protocolLabels(device.protocols)) ]),
			E('td', { 'class': 'td' }, [ text(device.manufacturer) ]),
			E('td', { 'class': 'td' }, [ text(deviceLabel(device)) ]),
			E('td', { 'class': 'td', 'style': 'font-family: monospace' }, [ text(device.serial) ])
			/* 以下详情单元格与表头同步隐藏。
			, E('td', { 'class': 'td' }, [ text(device.oui_vendor) ])
			, E('td', { 'class': 'td' }, [ text(device.firmware) ])
			, E('td', { 'class': 'td', 'style': 'word-break: break-all' }, [ serviceNode ])
			*/
		]));
	});

	return E('div', {}, [ sourceHelp, table ]);
}

return view.extend({
	callScan: rpc.declare({
		object: 'luci.ipc-discovery',
		method: 'scan',
		params: [],
		expect: { '': {} }
	}),

	callClearCache: rpc.declare({
		object: 'luci.ipc-discovery',
		method: 'clear_cache',
		params: [],
		expect: { '': {} }
	}),

	callDaemonStatus: rpc.declare({
		object: 'luci.ipc-discovery',
		method: 'daemon_status',
		params: [],
		expect: { '': {} }
	}),

	callDaemonStart: rpc.declare({
		object: 'luci.ipc-discovery',
		method: 'daemon_start',
		params: [],
		expect: { '': {} }
	}),

	callDaemonStop: rpc.declare({
		object: 'luci.ipc-discovery',
		method: 'daemon_stop',
		params: [],
		expect: { '': {} }
	}),

	load() {
		const self = this;
		return L.resolveDefault(this.callDaemonStatus(), {
			ok: false,
			running: false,
			enabled: false,
			error: _('查询发现服务状态失败')
		}).then(function(service) {
			/* Never trigger a scan while the user has disabled the daemon. */
			if (!service.running)
				return [ service, null ];
			return L.resolveDefault(self.callScan(), {
				code: -1,
				stdout: '',
				stderr: _('RPC 调用失败')
			}).then(function(reply) {
				return [ service, reply ];
			});
		});
	},

	render(data) {
		const self = this;
		const service = data[0] || { ok: false, running: false, enabled: false };
		const reply = data[1];
		const results = E('div');

		function resultNodes(currentReply) {
			const result = parseReply(currentReply);
			const iface = result.interface || {};
			const summary = result.ok ? E('p', {}, [
				E('strong', {}, [ _('接口') + '：' ]),
				text(iface.name),
				' — ',
				text(iface.address),
				' / ',
				text(iface.netmask),
				' — ',
				_('共 %d 台设备：%d 台协议确认，%d 台二层候选，%d 台命中 OUI；%d 台在线，%d 台最近出现；收到 %d 个数据报，耗时 %.3f 秒').format(
					Number(result.count || 0),
					Number(result.camera_count || 0),
					Number(result.candidate_count || 0),
					Number(result.oui_match_count || 0),
					Number(result.online_count || 0),
					Number(result.recent_count || 0),
					Number(result.datagrams_received || 0),
					Number(result.duration_ms || 0) / 1000
				)
			]) : E('div', { 'class': 'alert-message error' }, [
				E('strong', {}, [ _('发现失败') + '：' ]),
				text(result.error || currentReply && currentReply.stderr || _('未知错误'))
			]);

			return [ summary, renderWarnings(result.warnings), renderTable(result.devices) ];
		}

		if (service.running) {
			replaceContent(results, resultNodes(reply));
		}
		else {
			replaceContent(results, E('div', { 'class': 'alert-message notice' }, [
				service.ok
					? _('发现服务已停止：不会抓取或发送报文，扫描器不占用 CPU。')
					: _('无法查询发现服务状态：%s').format(service.error || _('未知错误'))
			]));
		}

		function setActionButtonsDisabled(disabled) {
			scanButton.disabled = disabled || !service.running;
			clearButton.disabled = disabled || !service.running;
			serviceButton.disabled = disabled;
		}

		const scanButton = E('button', {
			'class': 'btn cbi-button cbi-button-action important',
			'click': function(event) {
				event.preventDefault();
				setActionButtonsDisabled(true);
				self.callScan().then(function(nextReply) {
					replaceContent(results, resultNodes(nextReply));
					setActionButtonsDisabled(false);
				}, function(error) {
					replaceContent(results, resultNodes({ code: -1, stderr: String(error) }));
					setActionButtonsDisabled(false);
				});
			}
		}, [ _('立即扫描') ]);

		const clearButton = E('button', {
			'class': 'btn cbi-button cbi-button-negative',
			'click': function(event) {
				event.preventDefault();
				if (!window.confirm(_('确定清除全部内存发现缓存吗？')))
					return;
				setActionButtonsDisabled(true);
				self.callClearCache().then(function(nextReply) {
					replaceContent(results, resultNodes(nextReply));
					setActionButtonsDisabled(false);
				}, function(error) {
					replaceContent(results, resultNodes({ code: -1, stderr: String(error) }));
					setActionButtonsDisabled(false);
				});
			}
		}, [ _('清除缓存') ]);

		const serviceButton = E('button', {
			'class': service.running
				? 'btn cbi-button cbi-button-negative'
				: 'btn cbi-button cbi-button-action important',
			'click': function(event) {
				event.preventDefault();
				if (service.running && !window.confirm(
					_('确定停止发现服务并禁用开机启动吗？全部内存发现结果都会丢失。')
				))
					return;
				setActionButtonsDisabled(true);
				const action = service.running ? self.callDaemonStop() : self.callDaemonStart();
				action.then(function(nextService) {
					if (!nextService || !nextService.ok) {
						window.alert((nextService && nextService.error) || _('服务操作失败'));
						setActionButtonsDisabled(false);
						return;
					}
					window.location.reload();
				}, function(error) {
					window.alert(String(error));
					setActionButtonsDisabled(false);
				});
			}
		}, [ service.running ? _('停止发现服务') : _('启动发现服务') ]);

		scanButton.disabled = !service.running;
		clearButton.disabled = !service.running;

		const serviceSummary = E('div', {
			'class': service.running ? 'alert-message success' : 'alert-message warning'
		}, [
			E('strong', {}, [ _('发现服务') + '：' ]),
			service.running ? _('运行中') : _('已停止'),
			' — ',
			E('strong', {}, [ _('开机启动') + '：' ]),
			service.enabled ? _('已启用') : _('已禁用')
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ _('IPC 摄像机发现') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('发现服务持续在内存中缓存 ARP 和 DHCP 观察结果，并定期发送 ONVIF/WS-Discovery、Uniview、SADP、DVRIP 和 DHIP 探针。“制造商”优先采用协议响应，协议缺失时采用 OUI 厂商线索。请结合“状态”和“最后发现”判断设备是否仍在线。')
			]),
			E('div', { 'class': 'cbi-section' }, [
				serviceSummary,
				results,
				E('div', { 'class': 'cbi-page-actions' }, [
					serviceButton,
					' ',
					scanButton,
					' ',
					clearButton
				])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
