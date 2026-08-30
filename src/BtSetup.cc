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
#include "BtSetup.h"

#include <cstring>

#include "RequestGroup.h"
#include "DownloadEngine.h"
#include "Option.h"
#include "BtRegistry.h"
#include "PeerListenCommand.h"
#include "UtpConnection.h"
#include "TrackerWatcherCommand.h"
#include "SeedCheckCommand.h"
#include "PeerChokeCommand.h"
#include "ActivePeerConnectionCommand.h"
#include "PeerListenCommand.h"
#include "UnionSeedCriteria.h"
#include "TimeSeedCriteria.h"
#include "ShareRatioSeedCriteria.h"
#include "prefs.h"
#include "LogFactory.h"
#include "Logger.h"
#include "util.h"
#include "SegList.h"
#include "DHTGetPeersCommand.h"
#include "DHTPeerAnnounceStorage.h"
#include "DHTSetup.h"
#include "DHTRegistry.h"
#include "DHTNode.h"
#include "DHTRoutingTable.h"
#include "DHTTaskQueue.h"
#include "DHTTaskFactory.h"
#include "DHTTokenTracker.h"
#include "DHTMessageDispatcher.h"
#include "DHTMessageReceiver.h"
#include "DHTMessageFactory.h"
#include "DHTMessageCallback.h"
#include "UDPTrackerClient.h"
#include "UtpCommand.h"
#include "UtpContext.h"
#include "ReceiverMSEHandshakeCommand.h"
#include "BtProgressInfoFile.h"
#include "BtAnnounce.h"
#include "BtRuntime.h"
#include "bittorrent_helper.h"
#include "BtStopDownloadCommand.h"
#include "LpdReceiveMessageCommand.h"
#include "LpdDispatchMessageCommand.h"
#include "LpdMessageReceiver.h"
#include "LpdMessageDispatcher.h"
#include "message.h"
#include "SocketCore.h"
#include "DlAbortEx.h"
#include "array_fun.h"
#include "DownloadContext.h"
#include "PieceStorage.h"
#include "PeerStorage.h"
#include "fmt.h"

namespace aria2 {

BtSetup::BtSetup() = default;

void BtSetup::setup(std::vector<std::unique_ptr<Command>>& commands,
                    RequestGroup* requestGroup, DownloadEngine* e,
                    const Option* option)
{
  if (!requestGroup->getDownloadContext()->hasAttribute(CTX_ATTR_BT)) {
    return;
  }
  auto torrentAttrs =
      bittorrent::getTorrentAttrs(requestGroup->getDownloadContext());
  bool metadataGetMode = torrentAttrs->metadata.empty();
  auto& btReg = e->getBtRegistry();
  auto btObject = btReg->get(requestGroup->getGID());
  auto& pieceStorage = btObject->pieceStorage;
  auto& peerStorage = btObject->peerStorage;
  auto& btRuntime = btObject->btRuntime;
  auto& btAnnounce = btObject->btAnnounce;
  // commands
  {
    auto c = make_unique<TrackerWatcherCommand>(e->newCUID(), requestGroup, e);
    c->setPeerStorage(peerStorage);
    c->setPieceStorage(pieceStorage);
    c->setBtRuntime(btRuntime);
    c->setBtAnnounce(btAnnounce);

    commands.push_back(std::move(c));
  }
  if (!metadataGetMode) {
    auto c = make_unique<PeerChokeCommand>(e->newCUID(), e);
    c->setPeerStorage(peerStorage);
    c->setBtRuntime(btRuntime);

    commands.push_back(std::move(c));
  }
  {
    // 每秒检查一次是否需要发起新的 peer 连接（原 2s/3s），
    // 加快新发现的 peer 被实际连接的速度
    auto c = make_unique<ActivePeerConnectionCommand>(
        e->newCUID(), requestGroup, e, 1_s);
    c->setBtRuntime(btRuntime);
    c->setPieceStorage(pieceStorage);
    c->setPeerStorage(peerStorage);
    c->setBtAnnounce(btAnnounce);

    commands.push_back(std::move(c));
  }

  if (metadataGetMode || !torrentAttrs->privateTorrent) {
    if (DHTRegistry::isInitialized()) {
      auto command =
          make_unique<DHTGetPeersCommand>(e->newCUID(), requestGroup, e);
      command->setTaskQueue(DHTRegistry::getData().taskQueue.get());
      command->setTaskFactory(DHTRegistry::getData().taskFactory.get());
      command->setBtRuntime(btRuntime);
      command->setPeerStorage(peerStorage);
      commands.push_back(std::move(command));
    }
    if (DHTRegistry::isInitialized6()) {
      auto command =
          make_unique<DHTGetPeersCommand>(e->newCUID(), requestGroup, e);
      command->setTaskQueue(DHTRegistry::getData6().taskQueue.get());
      command->setTaskFactory(DHTRegistry::getData6().taskFactory.get());
      command->setBtRuntime(btRuntime);
      command->setPeerStorage(peerStorage);
      commands.push_back(std::move(command));
    }
  }
  if (!metadataGetMode) {
    auto unionCri = make_unique<UnionSeedCriteria>();
    if (option->defined(PREF_SEED_TIME)) {
      unionCri->addSeedCriteria(
          make_unique<TimeSeedCriteria>(std::chrono::seconds(
              static_cast<int>(option->getAsDouble(PREF_SEED_TIME) * 60))));
    }
    {
      double ratio = option->getAsDouble(PREF_SEED_RATIO);
      if (ratio > 0.0) {
        auto cri = make_unique<ShareRatioSeedCriteria>(
            option->getAsDouble(PREF_SEED_RATIO),
            requestGroup->getDownloadContext());
        cri->setPieceStorage(pieceStorage);
        cri->setBtRuntime(btRuntime);

        unionCri->addSeedCriteria(std::move(cri));
      }
    }
    if (!unionCri->getSeedCriterion().empty()) {
      auto c = make_unique<SeedCheckCommand>(e->newCUID(), requestGroup, e,
                                             std::move(unionCri));
      c->setPieceStorage(pieceStorage);
      c->setBtRuntime(btRuntime);
      commands.push_back(std::move(c));
    }
  }
  if (btReg->getTcpPort() == 0) {
    static int families[] = {AF_INET, AF_INET6};
    size_t familiesLength =
        e->getOption()->getAsBool(PREF_DISABLE_IPV6) ? 1 : 2;
    for (size_t i = 0; i < familiesLength; ++i) {
      auto command =
          make_unique<PeerListenCommand>(e->newCUID(), e, families[i]);
      bool ret;
      uint16_t port;
      if (btReg->getTcpPort()) {
        SegList<int> sgl;
        int usedPort = btReg->getTcpPort();
        sgl.add(usedPort, usedPort + 1);
        ret = command->bindPort(port, sgl);
      }
      else {
        auto sgl =
            util::parseIntSegments(e->getOption()->get(PREF_LISTEN_PORT));
        sgl.normalize();
        ret = command->bindPort(port, sgl);
      }
      if (ret) {
        btReg->setTcpPort(port);
        // Add command to DownloadEngine directly.
        e->addCommand(std::move(command));
      }
    }
    if (btReg->getTcpPort() == 0) {
      throw DL_ABORT_EX(_("Errors occurred while binding port.\n"));
    }

    // NAT traversal（UPnP/NAT-PMP 端口映射）已移到 DownloadEngine::setOption
    // 在引擎启动早期执行：此处（BT 任务创建路径）不能阻塞——首次添加 BT
    // 任务时 1.5~7.5s 的 SSDP/HTTP 等待会让引擎主线程卡死，RPC 超时表现为
    // 前端 "fetch failed"，且任务创建流程被拖入异常窗口。

    // uTP (BEP 29): host the transport for the whole process once.
    if (option->getAsBool(PREF_ENABLE_UTP)) {
      // 不能用进程级 static 标记：UtpCommand 在引擎空闲（所有任务
      // 结束）时按惯例退出，若标记不重置，此后新建的 BT 任务再也
      // 无人泵送 uTP（processTick/receiveLoop），出站 SYN 发出后
      // 必然超时，全部回退 TCP —— 症状即"peer 全显示 TCP"。
      // 改由 UtpContext 记录命令存活状态，命令退出后可重建。
      if (e->getUtpContext() && !e->getUtpContext()->hasLiveCommand()) {
        // 用与 TCP 监听相同的端口启动 uTP（标准 BT 约定：对端把
        // uTP SYN 发到我们通告的监听端口）。此前在引擎构造时绑定
        // 临时端口，入站 uTP 永远收不到 SYN——这就是"启用了 uTP
        // 却一个 uTP 连接都没有"的直接原因。
        if (!e->getUtpContext()->isStarted()) {
          e->getUtpContext()->start(btReg->getTcpPort());
        }
        e->addRoutineCommand(
            make_unique<utp::UtpCommand>(e->newCUID(), e));
        // Inbound uTP peers: on SYN, spawn the MSE sniffing/handshake
        // command over the uTP transport — identical to the TCP path
        // (it identifies plaintext vs encrypted handshake, negotiates
        // MSE when the peer offers it, and enforces forced-encryption).
        e->getUtpContext()->setAcceptHandler(
            [e](const std::shared_ptr<utp::UtpConnection>& conn) {
              const auto* opt = e->getOption();
              // 热更新：enable-utp 被关闭、或连接协议设为仅 TCP 时，
              // 拒绝新入站 uTP 连接（出站侧同样实时读取这些选项）。
              if (!opt->getAsBool(PREF_ENABLE_UTP) ||
                  opt->get(PREF_BT_CONNECT_PROTOCOL) == V_CONNECT_TCP) {
                A2_LOG_INFO(
                    "uTP: inbound connection rejected (uTP disabled via "
                    "option change; peer may retry over TCP)");
                return;
              }
              // 加密策略与 TCP 一致：明文/加密都接受，由嗅探分流；
              // 强制加密下收到明文握手会在命令内部按配置拒绝。
              auto peer = std::make_shared<Peer>(conn->getRemoteAddr(),
                                                 conn->getRemotePort(),
                                                 true /* incoming */);
              e->addCommand(make_unique<ReceiverMSEHandshakeCommand>(
                  e->newCUID(), peer, e, nullptr /* no TCP socket */, conn));
            });
        A2_LOG_INFO("uTP: transport driver installed");
      }
    }
  }
  btAnnounce->setTcpPort(btReg->getTcpPort());

  if (option->getAsBool(PREF_BT_ENABLE_LPD) && btReg->getTcpPort() &&
      (metadataGetMode || !torrentAttrs->privateTorrent)) {
    if (!btReg->getLpdMessageReceiver()) {
      A2_LOG_INFO("Initializing LpdMessageReceiver.");
      auto receiver = std::make_shared<LpdMessageReceiver>(LPD_MULTICAST_ADDR,
                                                           LPD_MULTICAST_PORT);
      bool initialized = false;
      const std::string& lpdInterface =
          e->getOption()->get(PREF_BT_LPD_INTERFACE);
      if (lpdInterface.empty()) {
        if (receiver->init("")) {
          initialized = true;
        }
      }
      else {
        auto ifAddrs = SocketCore::getInterfaceAddress(lpdInterface, AF_INET,
                                                       AI_NUMERICHOST);
        for (const auto& soaddr : ifAddrs) {
          char host[NI_MAXHOST];
          if (inetNtop(AF_INET, &soaddr.su.in.sin_addr, host, sizeof(host)) ==
                  0 &&
              receiver->init(host)) {
            initialized = true;
            break;
          }
        }
      }
      if (initialized) {
        btReg->setLpdMessageReceiver(receiver);
        A2_LOG_INFO(fmt("LpdMessageReceiver initialized. multicastAddr=%s:%u,"
                        " localAddr=%s",
                        LPD_MULTICAST_ADDR, LPD_MULTICAST_PORT,
                        receiver->getLocalAddress().c_str()));
        e->addCommand(
            make_unique<LpdReceiveMessageCommand>(e->newCUID(), receiver, e));
      }
      else {
        A2_LOG_INFO("LpdMessageReceiver not initialized.");
      }
    }
    if (btReg->getLpdMessageReceiver()) {
      const unsigned char* infoHash =
          bittorrent::getInfoHash(requestGroup->getDownloadContext());
      A2_LOG_INFO("Initializing LpdMessageDispatcher.");
      auto dispatcher = std::make_shared<LpdMessageDispatcher>(
          std::string(&infoHash[0], &infoHash[INFO_HASH_LENGTH]),
          btReg->getTcpPort(), LPD_MULTICAST_ADDR, LPD_MULTICAST_PORT);
      if (dispatcher->init(btReg->getLpdMessageReceiver()->getLocalAddress(),
                           /*ttl*/ 1, /*loop*/ 1)) {
        A2_LOG_INFO("LpdMessageDispatcher initialized.");
        auto cmd =
            make_unique<LpdDispatchMessageCommand>(e->newCUID(), dispatcher, e);
        cmd->setBtRuntime(btRuntime);
        e->addCommand(std::move(cmd));
      }
      else {
        A2_LOG_INFO("LpdMessageDispatcher not initialized.");
      }
    }
  }
  auto btStopTimeout = option->getAsInt(PREF_BT_STOP_TIMEOUT);
  if (btStopTimeout > 0) {
    auto stopDownloadCommand = make_unique<BtStopDownloadCommand>(
        e->newCUID(), requestGroup, e, std::chrono::seconds(btStopTimeout));
    stopDownloadCommand->setBtRuntime(btRuntime);
    stopDownloadCommand->setPieceStorage(pieceStorage);
    commands.push_back(std::move(stopDownloadCommand));
  }
  btRuntime->setReady(true);
}

} // namespace aria2
