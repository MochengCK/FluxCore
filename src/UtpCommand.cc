/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2026 The XferCore Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#include "UtpCommand.h"

#include "DownloadEngine.h"
#include "RequestGroupMan.h"
#include "UtpContext.h"

namespace aria2 {
namespace utp {

UtpCommand::UtpCommand(cuid_t cuid, DownloadEngine* e) : Command{cuid}, e_{e}
{
  setStatusRealtime();
  if (auto* ctx = e_->getUtpContext()) {
    ctx->setCommandAlive(true);
    // 把共享 UDP socket 注册进引擎事件循环。此前 uTP 数据只能靠
    // routine command 的 1s 轮询（DEFAULT_REFRESH_INTERVAL）处理，
    // 每个 uTP 往返至少 1s，SYN/BT 握手与 piece 数据吞吐被压到每秒
    // 一轮——表现为大量 peer 卡在握手、BT 下载永远没速度。注册读
    // 事件后，对端 SYN-ACK/数据包一到达，主循环 poll 立即返回并驱动
    // 本命令 receiveLoop() 及时排水。
    if (ctx->isStarted()) {
      e_->addSocketForReadCheck(ctx->getSocket(), this);
    }
  }
}

UtpCommand::~UtpCommand()
{
  // 标记本命令已消亡：downloadFinished() 退出后 BtSetup 会在下一个
  // BT 任务时重建 UtpCommand，恢复 processTick/receiveLoop 泵送。
  if (auto* ctx = e_->getUtpContext()) {
    ctx->setCommandAlive(false);
    // 注销 UDP socket 读事件，避免命令销毁后事件循环持有悬垂指针。
    if (ctx->getSocket()) {
      e_->deleteSocketForReadCheck(ctx->getSocket(), this);
    }
  }
}

bool UtpCommand::execute()
{
  auto ctx = e_->getUtpContext();
  if (!ctx) {
    return true;
  }
  // 与 PeerListenCommand / DHTInteractionCommand 一致的退出条件：
  // 引擎停机或全部任务结束时必须退出，否则 routineCommands_ 永不为
  // 空，DownloadEngine 主循环无法结束（引擎无法正常停机）。
  if (e_->isHaltRequested() ||
      e_->getRequestGroupMan()->downloadFinished()) {
    return true;
  }
  // Advance all connections (timers / CC / retransmit / sends) and
  // drain the UDP socket. Both are non-blocking.
  ctx->processTick();
  ctx->receiveLoop();
  // Keep running for the engine's lifetime (like DHTInteractionCommand).
  e_->addRoutineCommand(std::unique_ptr<Command>(this));
  return false;
}

} // namespace utp
} // namespace aria2
