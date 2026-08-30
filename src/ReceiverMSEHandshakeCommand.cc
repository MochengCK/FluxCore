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
#include "ReceiverMSEHandshakeCommand.h"
#include "SocketLike.h"
#include "UtpSocketLike.h"
#include "UtpConnection.h"
#include "PeerReceiveHandshakeCommand.h"
#include "PeerConnection.h"
#include "DownloadEngine.h"
#include "BtHandshakeMessage.h"
#include "DlAbortEx.h"
#include "Peer.h"
#include "message.h"
#include "SocketCore.h"
#include "Logger.h"
#include "prefs.h"
#include "Option.h"
#include "MSEHandshake.h"
#include "ARC4Encryptor.h"
#include "RequestGroupMan.h"
#include "BtRegistry.h"
#include "DownloadContext.h"
#include "array_fun.h"

namespace aria2 {

ReceiverMSEHandshakeCommand::ReceiverMSEHandshakeCommand(
    cuid_t cuid, const std::shared_ptr<Peer>& peer, DownloadEngine* e,
    const std::shared_ptr<SocketCore>& s,
    const std::shared_ptr<utp::UtpConnection>& utpConn)
    : PeerAbstractCommand(cuid, peer, e, s),
      sequence_(RECEIVER_IDENTIFY_HANDSHAKE),
      isUtp_(utpConn != nullptr),
      utpConn_(utpConn),
      transport_(isUtp_
                     ? std::static_pointer_cast<SocketLike>(
                           std::make_shared<UtpSocketLike>(utpConn))
                     : std::make_shared<TcpSocketLike>(s)),
      mseHandshake_(
          make_unique<MSEHandshake>(cuid, transport_, e->getOption()))
{
  setTimeout(std::chrono::seconds(
      e->getOption()->getAsInt(PREF_PEER_CONNECTION_TIMEOUT)));
  mseHandshake_->setWantRead(true);
}

ReceiverMSEHandshakeCommand::~ReceiverMSEHandshakeCommand() = default;

bool ReceiverMSEHandshakeCommand::exitBeforeExecute()
{
  return getDownloadEngine()->isHaltRequested() ||
         getDownloadEngine()->getRequestGroupMan()->downloadFinished();
}

bool ReceiverMSEHandshakeCommand::executeInternal()
{
  // uTP：连接失败/超时/被 RST 时 transport 不可用，快速失败。
  if (isUtp_ && !transport_->isOpen()) {
    throw DL_ABORT_EX("uTP connection closed during MSE handshake");
  }
  if (mseHandshake_->getWantRead()) {
    mseHandshake_->read();
  }
  bool done = false;
  while (!done) {
    switch (sequence_) {
    case RECEIVER_IDENTIFY_HANDSHAKE: {
      MSEHandshake::HANDSHAKE_TYPE type =
          mseHandshake_->identifyHandshakeType();
      switch (type) {
      case MSEHandshake::HANDSHAKE_NOT_YET:
        done = true;
        break;
      case MSEHandshake::HANDSHAKE_ENCRYPTED:
        mseHandshake_->initEncryptionFacility(false);
        sequence_ = RECEIVER_WAIT_KEY;
        break;
      case MSEHandshake::HANDSHAKE_LEGACY: {
        const auto option = getDownloadEngine()->getOption();
        if (option->getAsBool(PREF_BT_FORCE_ENCRYPTION) ||
            option->getAsBool(PREF_BT_REQUIRE_CRYPTO)) {
          throw DL_ABORT_EX(
              "The legacy BitTorrent handshake is not acceptable by the"
              " preference.");
        }
        std::unique_ptr<SocketLike> peerTransport =
            isUtp_
                ? std::unique_ptr<SocketLike>(
                      make_unique<UtpSocketLike>(utpConn_))
                : make_unique<TcpSocketLike>(getSocket());
        auto peerConnection = make_unique<PeerConnection>(
            getCuid(), getPeer(), std::move(peerTransport));
        peerConnection->presetBuffer(mseHandshake_->getBuffer(),
                                     mseHandshake_->getBufferLength());
        getDownloadEngine()->addCommand(
            make_unique<PeerReceiveHandshakeCommand>(
                getCuid(), getPeer(), getDownloadEngine(),
                isUtp_ ? std::shared_ptr<SocketCore>() : getSocket(),
                std::move(peerConnection)));
        return true;
      }
      default:
        throw DL_ABORT_EX("Not supported handshake type.");
      }
      break;
    }
    case RECEIVER_WAIT_KEY: {
      if (mseHandshake_->receivePublicKey()) {
        mseHandshake_->sendPublicKey();
        sequence_ = RECEIVER_SEND_KEY_PENDING;
      }
      else {
        done = true;
      }
      break;
    }
    case RECEIVER_SEND_KEY_PENDING:
      if (mseHandshake_->send()) {
        sequence_ = RECEIVER_FIND_HASH_MARKER;
      }
      else {
        done = true;
      }
      break;
    case RECEIVER_FIND_HASH_MARKER: {
      if (mseHandshake_->findReceiverHashMarker()) {
        sequence_ = RECEIVER_RECEIVE_PAD_C_LENGTH;
      }
      else {
        done = true;
      }
      break;
    }
    case RECEIVER_RECEIVE_PAD_C_LENGTH: {
      std::vector<std::shared_ptr<DownloadContext>> downloadContexts;
      getDownloadEngine()->getBtRegistry()->getAllDownloadContext(
          std::back_inserter(downloadContexts));
      if (mseHandshake_->receiveReceiverHashAndPadCLength(downloadContexts)) {
        sequence_ = RECEIVER_RECEIVE_PAD_C;
      }
      else {
        done = true;
      }
      break;
    }
    case RECEIVER_RECEIVE_PAD_C: {
      if (mseHandshake_->receivePad()) {
        sequence_ = RECEIVER_RECEIVE_IA_LENGTH;
      }
      else {
        done = true;
      }
      break;
    }
    case RECEIVER_RECEIVE_IA_LENGTH: {
      if (mseHandshake_->receiveReceiverIALength()) {
        sequence_ = RECEIVER_RECEIVE_IA;
      }
      else {
        done = true;
      }
      break;
    }
    case RECEIVER_RECEIVE_IA: {
      if (mseHandshake_->receiveReceiverIA()) {
        mseHandshake_->sendReceiverStep2();
        sequence_ = RECEIVER_SEND_STEP2_PENDING;
      }
      else {
        done = true;
      }
      break;
    }
    case RECEIVER_SEND_STEP2_PENDING:
      if (mseHandshake_->send()) {
        createCommand();
        return true;
      }
      else {
        done = true;
      }
      break;
    }
  }
  // uTP：不注册 fd 事件，靠每轮调度轮询推进（数据由 UtpCommand 泵送）。
  if (!isUtp_) {
    if (mseHandshake_->getWantRead()) {
      setReadCheckSocket(getSocket());
    }
    else {
      disableReadCheckSocket();
    }
    if (mseHandshake_->getWantWrite()) {
      setWriteCheckSocket(getSocket());
    }
    else {
      disableWriteCheckSocket();
    }
  }
  addCommandSelf();
  return false;
}

void ReceiverMSEHandshakeCommand::createCommand()
{
  std::unique_ptr<SocketLike> peerTransport =
      isUtp_ ? std::unique_ptr<SocketLike>(make_unique<UtpSocketLike>(utpConn_))
             : make_unique<TcpSocketLike>(getSocket());
  auto peerConnection = make_unique<PeerConnection>(
      getCuid(), getPeer(), std::move(peerTransport));
  if (mseHandshake_->getNegotiatedCryptoType() == MSEHandshake::CRYPTO_ARC4) {
    peerConnection->enableEncryption(mseHandshake_->popEncryptor(),
                                     mseHandshake_->popDecryptor());
  }
  // Since initiator cannot send payload stream before reading step2
  // from receiver, mseHandshake_->getBufferLength() should be 0.
  peerConnection->presetBuffer(mseHandshake_->getIA(),
                               mseHandshake_->getIALength());
  // TODO add mseHandshake_->getInfoHash() to PeerReceiveHandshakeCommand
  // as a hint. If this info hash and one in BitTorrent Handshake does not
  // match, then drop connection.
  getDownloadEngine()->addCommand(make_unique<PeerReceiveHandshakeCommand>(
      getCuid(), getPeer(), getDownloadEngine(),
      isUtp_ ? std::shared_ptr<SocketCore>() : getSocket(),
      std::move(peerConnection)));
}

} // namespace aria2
