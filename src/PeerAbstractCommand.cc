/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
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
#include "PeerAbstractCommand.h"
#include "Peer.h"
#include "DownloadEngine.h"
#include "Option.h"
#include "DlAbortEx.h"
#include "SocketCore.h"
#include "Logger.h"
#include "LogFactory.h"
#include "message.h"
#include "prefs.h"
#include "DownloadFailureException.h"
#include "fmt.h"
#include "wallclock.h"
#include "util.h"

namespace aria2 {

PeerAbstractCommand::PeerAbstractCommand(cuid_t cuid,
                                         const std::shared_ptr<Peer>& peer,
                                         DownloadEngine* e,
                                         const std::shared_ptr<SocketCore>& s)
    : Command(cuid),
      checkPoint_(global::wallclock()),
      // TODO referring global option
      timeout_(std::chrono::seconds(e->getOption()->getAsInt(PREF_BT_TIMEOUT))),
      e_(e),
      socket_(s),
      peer_(peer),
      checkSocketIsReadable_(false),
      checkSocketIsWritable_(false),
      noCheck_(false)
{
  if (socket_ && socket_->isOpen()) {
    setReadCheckSocket(socket_);
  }
}

PeerAbstractCommand::~PeerAbstractCommand()
{
  disableReadCheckSocket();
  disableWriteCheckSocket();
}

bool PeerAbstractCommand::execute()
{
  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " -"
                   " socket: read:%d, write:%d, hup:%d, err:%d, noCheck:%d",
                   getCuid(), readEventEnabled(), writeEventEnabled(),
                   hupEventEnabled(), errorEventEnabled(), noCheck_));
  if (exitBeforeExecute()) {
    onAbort();
    return true;
  }
  try {
    // uTP 传输（socket_ == nullptr）没有 SocketCore 事件：IO 由
    // utp::UtpCommand 的 processTick/receiveLoop 泵送，本命令每轮被
    // 引擎直接调度。因此不能用 socket 事件来刷新 checkPoint_——否则
    // checkPoint_ 永远不更新，120s（PREF_BT_TIMEOUT）后连接被超时
    // abort，即使 uTP 握手正在正常进行中。对 uTP 连接，每次
    // executeInternal() 成功执行就刷新 checkPoint_（等价于 noCheck_）。
    // 超时检测改为依赖 UtpConnection 自身的 RTO/handleTimeout 机制
    // （SYN 重试 4 次、数据重传 2 次 RTO 后 error_=true），UtpSocketLike
    // 在连接 CLOSED/error 时会让 receiveHandshake 抛 EOF，触发本命令
    // 的异常路径正常退出。
    if (!socket_) {
      // uTP：跳过所有 socket 事件检查，直接刷新 checkPoint_ 并执行。
      checkPoint_ = global::wallclock();
    }
    else if (noCheck_ || (checkSocketIsReadable_ && readEventEnabled()) ||
        (checkSocketIsWritable_ && writeEventEnabled()) || hupEventEnabled()) {
      checkPoint_ = global::wallclock();
    }
    else if (errorEventEnabled()) {
      throw DL_ABORT_EX(
          fmt(MSG_NETWORK_PROBLEM, socket_->getSocketError().c_str()));
    }
    if (checkPoint_.difference(global::wallclock()) >= timeout_) {
      throw DL_ABORT_EX(EX_TIME_OUT);
    }
    return executeInternal();
  }
  catch (DownloadFailureException& err) {
    A2_LOG_ERROR_EX(EX_DOWNLOAD_ABORTED, err);
    onConnectionFailed();
    onAbort();
    onFailure(err);
    return true;
  }
  catch (RecoverableException& err) {
    A2_LOG_DEBUG_EX(fmt(MSG_TORRENT_DOWNLOAD_ABORTED, getCuid()), err);
    A2_LOG_DEBUG(fmt(MSG_PEER_BANNED, getCuid(), peer_->getIPAddress().c_str(),
                     peer_->getPort()));
    onConnectionFailed();
    onAbort();
    return prepareForNextPeer(0);
  }
}

// TODO this method removed when PeerBalancerCommand is implemented
bool PeerAbstractCommand::prepareForNextPeer(time_t wait) { return true; }

void PeerAbstractCommand::disableReadCheckSocket()
{
  if (checkSocketIsReadable_) {
    e_->deleteSocketForReadCheck(readCheckTarget_, this);
    checkSocketIsReadable_ = false;
    readCheckTarget_.reset();
  }
}

void PeerAbstractCommand::setReadCheckSocket(
    const std::shared_ptr<SocketCore>& socket)
{
  if (!socket->isOpen()) {
    disableReadCheckSocket();
  }
  else {
    if (checkSocketIsReadable_) {
      if (*readCheckTarget_ != *socket) {
        e_->deleteSocketForReadCheck(readCheckTarget_, this);
        e_->addSocketForReadCheck(socket, this);
        readCheckTarget_ = socket;
      }
    }
    else {
      e_->addSocketForReadCheck(socket, this);
      checkSocketIsReadable_ = true;
      readCheckTarget_ = socket;
    }
  }
}

void PeerAbstractCommand::disableWriteCheckSocket()
{
  if (checkSocketIsWritable_) {
    e_->deleteSocketForWriteCheck(writeCheckTarget_, this);
    checkSocketIsWritable_ = false;
    writeCheckTarget_.reset();
  }
}

void PeerAbstractCommand::setWriteCheckSocket(
    const std::shared_ptr<SocketCore>& socket)
{
  if (!socket->isOpen()) {
    disableWriteCheckSocket();
  }
  else {
    if (checkSocketIsWritable_) {
      if (*writeCheckTarget_ != *socket) {
        e_->deleteSocketForWriteCheck(writeCheckTarget_, this);
        e_->addSocketForWriteCheck(socket, this);
        writeCheckTarget_ = socket;
      }
    }
    else {
      e_->addSocketForWriteCheck(socket, this);
      checkSocketIsWritable_ = true;
      writeCheckTarget_ = socket;
    }
  }
}

void PeerAbstractCommand::setNoCheck(bool check) { noCheck_ = check; }

void PeerAbstractCommand::updateKeepAlive()
{
  checkPoint_ = global::wallclock();
}

void PeerAbstractCommand::createSocket()
{
  socket_ = std::make_shared<SocketCore>();
}

void PeerAbstractCommand::addCommandSelf()
{
  e_->addCommand(std::unique_ptr<Command>(this));
}

} // namespace aria2
