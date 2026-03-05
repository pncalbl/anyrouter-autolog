#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

# 浏览器无头模式：True=不显示浏览器窗口（服务器环境），False=显示浏览器窗口（本地调试）
HEADLESS = True
BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'🔄 [处理中] {account_name}: 正在启动浏览器获取 WAF cookies...')

	async with async_playwright() as p:
		import tempfile

		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=HEADLESS,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				print(f'🔄 [处理中] {account_name}: 正在访问登录页面获取初始 cookies...')

				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				print(f'ℹ️ [信息] {account_name}: 已获取 {len(waf_cookies)} 个 WAF cookies')

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					print(f'❌ [失败] {account_name}: 缺少 WAF cookies: {missing_cookies}')
					await context.close()
					return None

				print(f'✅ [成功] {account_name}: 成功获取所有 WAF cookies')

				await context.close()

				return waf_cookies

			except Exception as e:
				print(f'❌ [失败] {account_name}: 获取 WAF cookies 时发生错误: {e}')
				await context.close()
				return None


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
					'display': f'💰 已使用: ${used_quota}, 当前余额: 💵${quota}',
				}
		return {'success': False, 'error': f'❌ 获取用户信息失败: HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'❌ 获取用户信息失败: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			print(f'❌ [失败] {account_name}: 无法获取 WAF cookies')
			return None
	else:
		print(f'ℹ️ [信息] {account_name}: 无需绕过 WAF，直接使用用户 cookies')

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	print(f'🌐 [网络] {account_name}: 正在执行签到')

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	print(f'📡 [响应] {account_name}: 响应状态码 {response.status_code}')

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				print(f'✅ [成功] {account_name}: 签到成功！')
				return True
			else:
				error_msg = result.get('msg', result.get('message', '未知错误'))
				# 检查是否是"已经签到过"的情况，这种情况也算成功
				already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
				if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
					print(f'✅ [成功] {account_name}: 今日已签到')
					return True
				print(f'❌ [失败] {account_name}: 签到失败 - {error_msg}')
				return False
		except json.JSONDecodeError:
			# 如果不是 JSON 响应，检查是否包含成功标识
			if 'success' in response.text.lower():
				print(f'✅ [成功] {account_name}: 签到成功！')
				return True
			else:
				print(f'❌ [失败] {account_name}: 签到失败 - 响应格式无效')
				return False
	else:
		print(f'❌ [失败] {account_name}: 签到失败 - HTTP {response.status_code}')
		return False


def format_check_in_notification(detail: dict) -> str:
	"""格式化签到通知消息"""
	lines = [
		f'[签到] {detail["name"]}',
		'  ━━━━━━━━━━━━━━━━━━━━',
		'  📍 签到前',
		f'     💵 余额: ${detail["before_quota"]:.2f}  |  📊 累计消耗: ${detail["before_used"]:.2f}',
		'  📍 签到后',
		f'     💵 余额: ${detail["after_quota"]:.2f}  |  📊 累计消耗: ${detail["after_used"]:.2f}',
	]

	# 判断是否有变化
	has_reward = detail['check_in_reward'] != 0
	has_usage = detail['usage_increase'] != 0

	if has_reward or has_usage:
		lines.append('  ━━━━━━━━━━━━━━━━━━━━')

		# 已签到但期间有使用
		if not has_reward and has_usage:
			lines.append('  ℹ️  今日已签到（期间有使用）')

		# 签到获得
		if has_reward:
			lines.append(f'  🎁 签到获得: +${detail["check_in_reward"]:.2f}')

		# 期间消耗
		if has_usage:
			lines.append(f'  📉 期间消耗: ${detail["usage_increase"]:.2f}')

		# 余额变化
		if detail['balance_change'] != 0:
			change_symbol = '+' if detail['balance_change'] > 0 else ''
			change_emoji = '📈' if detail['balance_change'] > 0 else '📉'
			lines.append(f'  {change_emoji} 余额变化: {change_symbol}${detail["balance_change"]:.2f}')
	else:
		# 无任何变化
		lines.extend(['  ━━━━━━━━━━━━━━━━━━━━', '  ℹ️  今日已签到，无变化'])

	return '\n'.join(lines)


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n🔄 [处理中] 开始处理 {account_name}')

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		print(f'❌ [失败] {account_name}: 配置中未找到服务商 "{account.provider}"')
		return False, None, None

	print(f'ℹ️ [信息] {account_name}: 使用服务商 "{account.provider}" ({provider_config.domain})')

	user_cookies = parse_cookies(account.cookies)
	if not user_cookies:
		print(f'❌ [失败] {account_name}: 配置格式无效')
		return False, None, None

	all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
	if not all_cookies:
		return False, None, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: account.api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info_before = get_user_info(client, headers, user_info_url)
		if user_info_before and user_info_before.get('success'):
			print(user_info_before['display'])
		elif user_info_before:
			print(user_info_before.get('error', '未知错误'))

		if provider_config.needs_manual_check_in():
			success = execute_check_in(client, account_name, provider_config, headers)
			# 签到后再次获取用户信息，用于计算签到收益
			user_info_after = get_user_info(client, headers, user_info_url)
			return success, user_info_before, user_info_after
		else:
			print(f'ℹ️ [信息] {account_name}: 签到已自动完成（由用户信息请求触发）')
			# 自动签到的情况，再次获取用户信息
			user_info_after = get_user_info(client, headers, user_info_url)
			return True, user_info_before, user_info_after

	except Exception as e:
		print(f'❌ [失败] {account_name}: 签到过程中发生错误 - {str(e)[:50]}...')
		return False, None, None
	finally:
		client.close()


async def main():
	"""主函数"""
	print('🚀 [系统] AnyRouter.top 多账号自动签到脚本已启动 (使用 Playwright)')
	print(f'⏰ [时间] 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	app_config = AppConfig.load_from_env()
	print(f'ℹ️ [信息] 已加载 {len(app_config.providers)} 个服务商配置')

	accounts = load_accounts_config()
	if not accounts:
		print('❌ [失败] 无法加载账号配置，程序退出')
		sys.exit(1)

	print(f'ℹ️ [信息] 发现 {len(accounts)} 个账号配置')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	account_check_in_details = {}  # 存储每个账号的签到详情
	# 检查是否设置了总是通知的环境变量（默认为 false，只在余额变化或失败时通知）
	always_notify_env = os.getenv('ALWAYS_NOTIFY', 'false').lower()
	always_notify = always_notify_env in ['true', '1', 'yes']
	need_notify = always_notify  # 如果设置了总是通知，则默认需要通知
	balance_changed = False  # 余额是否有变化

	# 记录成功和失败的账号名称
	success_accounts = []
	failed_accounts = []

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		account_name = account.get_display_name(i)
		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1
				success_accounts.append(account_name)
			else:
				failed_accounts.append(account_name)

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True
				print(f'🔔 [通知] {account_name} 失败，将发送通知')

			# 存储签到前后的余额信息
			if user_info_after and user_info_after.get('success'):
				current_quota = user_info_after['quota']
				current_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

				# 计算签到收益
				if user_info_before and user_info_before.get('success'):
					before_quota = user_info_before['quota']
					before_used = user_info_before['used_quota']
					after_quota = user_info_after['quota']
					after_used = user_info_after['used_quota']

					# 计算总额度（余额 + 历史消耗）
					total_before = before_quota + before_used
					total_after = after_quota + after_used

					# 签到获得的额度 = 总额度增加量
					check_in_reward = total_after - total_before

					# 本次消耗 = 历史消耗增加量
					usage_increase = after_used - before_used

					# 余额变化
					balance_change = after_quota - before_quota

					account_check_in_details[account_key] = {
						'name': account.get_display_name(i),
						'before_quota': before_quota,
						'before_used': before_used,
						'after_quota': after_quota,
						'after_used': after_used,
						'check_in_reward': check_in_reward,
						'usage_increase': usage_increase,
						'balance_change': balance_change,
						'success': success,
					}

			if should_notify_this_account:
				status = '✅ [成功]' if success else '❌ [失败]'
				account_result = f'{status} {account_name}'
				if user_info_after and user_info_after.get('success'):
					account_result += f'\n{user_info_after["display"]}'
				elif user_info_after:
					account_result += f'\n{user_info_after.get("error", "未知错误")}'
				notification_content.append(account_result)

		except Exception as e:
			failed_accounts.append(account_name)
			print(f'❌ [失败] {account_name} 处理异常: {e}')
			need_notify = True  # 异常也需要通知
			notification_content.append(f'❌ [失败] {account_name} 异常: {str(e)[:50]}...')

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('🔔 [通知] 检测到首次运行，将发送包含当前余额的通知')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('🔔 [通知] 检测到余额变化，将发送通知')
		else:
			print('ℹ️ [信息] 未检测到余额变化')

	# 为有余额变化的情况添加所有成功账号到通知内容
	# 或者如果设置了总是通知，也添加所有账号余额
	if balance_changed or always_notify:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in account_check_in_details:
				detail = account_check_in_details[account_key]
				account_name = detail['name']

				# 使用格式化函数生成通知消息
				account_result = format_check_in_notification(detail)

				# 检查是否已经在通知内容中（避免重复）
				if not any(account_name in item for item in notification_content):
					notification_content.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and notification_content:
		# 构建通知内容
		summary = ['📊 [统计] 签到结果统计:']

		# 显示成功和失败的账号
		if success_count == total_count:
			# 全部成功时，将所有账号合并在一行显示
			success_names_formatted = '】、【'.join(success_accounts)
			summary.append(f'✅ [成功] 【{success_names_formatted}】账号签到成功！')
		else:
			# 部分成功或全部失败时，分别显示成功和失败的账号
			if success_accounts:
				success_names_formatted = '】、【'.join(success_accounts)
				summary.append(f'✅ [成功] 【{success_names_formatted}】签到成功！')
			if failed_accounts:
				failed_names_formatted = '】、【'.join(failed_accounts)
				summary.append(f'❌ [失败] 【{failed_names_formatted}】签到失败！')

		# 总结
		if success_count == total_count:
			summary.append('🎉 [成功] 所有账号签到成功！')
		elif success_count > 0:
			summary.append('⚠️ [警告] 部分账号签到成功！')
		else:
			summary.append('❌ [错误] 所有账号签到失败！')

		time_info = f'⏰ [时间] {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])

		print(notify_content)
		notify.push_message('🔔 AnyRouter 签到提醒', notify_content, msg_type='text')
		if always_notify:
			print('🔔 [通知] 已发送通知（总是通知模式）')
		else:
			print('🔔 [通知] 由于失败或余额变化已发送通知')
	else:
		print('ℹ️ [信息] 所有账号成功且未检测到余额变化，跳过通知')

	# 返回退出码
	return 0 if success_count > 0 else 1


def run_main():
	"""运行主函数的包装函数"""
	try:
		exit_code = asyncio.run(main())
		sys.exit(exit_code)
	except KeyboardInterrupt:
		print('\n⚠️ [警告] 程序被用户中断')
		sys.exit(1)
	except Exception as e:
		print(f'\n❌ [失败] 程序执行过程中发生错误: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
