/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information
    
    Abstract:
    View controller class that manages display of properties related to automatic waiting
*/

import UIKit
import AVFoundation

/// View controller to display the current property values of a given AVPlayer and its current AVPlayerItem
@objcMembers class PlaybackDetailsViewController: UIViewController {
    
    // MARK: Properties
    @IBOutlet weak var rateLabel : UILabel!
    @IBOutlet weak var timeControlStatusLabel : UILabel!
    @IBOutlet weak var reasonForWaitingLabel : UILabel!
    @IBOutlet weak var likelyToKeepUpLabel : UILabel!
    @IBOutlet weak var loadedTimeRangesLabel : UILabel!
    @IBOutlet weak var currentTimeLabel: UILabel!
    @IBOutlet weak var playbackBufferFullLabel: UILabel!
    @IBOutlet weak var playbackBufferEmptyLabel: UILabel!
    @IBOutlet weak var timebaseRateLabel: UILabel!
    
    //KVO needs to be of a non optional variable so it preinitialized and observers are redone once it changes
    dynamic var player : AVPlayer = AVPlayer() {
        didSet {
            if  isViewLoaded {
                self.registerObserversPlayer()
            }
        }
    }
    
    //KVO needs to be of a non optional variable so it preinitialized and observers are redone once it changes
    dynamic var playerItem = AVPlayerItem(url: URL(string: "http://example.com")!) {
        didSet {
            if  isViewLoaded {
                self.registerObserversPlayerItem()
            }
        }
    }
    
    // AVPlayerItem.currentTime() and the AVPlayerItem.timebase's rate are not KVO observable. We check their values regularly using this timer.
    private let nonObservablePropertiesUpdateTimer = DispatchSource.makeTimerSource(flags: [], queue: DispatchQueue.main)
    
    var rateObservation: NSKeyValueObservation?
    var timeControlStatusObservation: NSKeyValueObservation?
    var reasonForWaitingToPlayObservation: NSKeyValueObservation?
    var playbackLikelyToKeepUpObservation: NSKeyValueObservation?
    var loadedTimeRangesObservation: NSKeyValueObservation?
    var playbackBufferFullObservation: NSKeyValueObservation?
    var playbackBufferEmptyObservation: NSKeyValueObservation?
    
    // MARK: View Life Cycle
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        nonObservablePropertiesUpdateTimer.setEventHandler { [weak self] in
            self?.updateNonObservableProperties()
        }
        nonObservablePropertiesUpdateTimer.schedule(deadline: DispatchTime.now(), repeating: DispatchTimeInterval.milliseconds(100))
        nonObservablePropertiesUpdateTimer.resume()
        registerObserversPlayer()
        registerObserversPlayerItem()
        
        //register observer with optional
        addObserver(self, forKeyPath: #keyPath(PlaybackDetailsViewController.player.currentItem.playbackLikelyToKeepUp), options: [.new, .initial], context: &observerContext)
        
    }
    
    deinit {
        // Un-register observers
        removeObserver(self, forKeyPath: #keyPath(PlaybackDetailsViewController.player.currentItem.playbackLikelyToKeepUp), context: &observerContext)
    }
    
    // MARK: Property Change Handlers
    func registerObserversPlayer() {
        
        //Update the UI as AVPlayer properties change.
        
        self.rateObservation = observe(\.player.rate) { (object, change) in
            object.rateLabel.text = object.player.rate.description
            print("rateObservation")
        }
        
        self.timeControlStatusObservation = observe(\.player.timeControlStatus) { (object, change) in
            object.timeControlStatusLabel.text = object.player.timeControlStatus.description
            object.timeControlStatusLabel.backgroundColor = object.labelBackgroundColor(forTimeControlStatus: object.player.timeControlStatus)
            print("timeControlStatusObservation")
        }
        self.reasonForWaitingToPlayObservation = observe(\.player.reasonForWaitingToPlay) { (object, change) in
            var text = "-"
            if let reasonForWaiting = object.player.reasonForWaitingToPlay {
                text = object.abbreviatedDescription(forReasonForWaitingToPlay: reasonForWaiting)
            }
            object.reasonForWaitingLabel.text = text
            print("reasonForWaitingToPlayObservation")
        }
    }
    
    func registerObserversPlayerItem() {
        
        //working alternatives for kvo
//        self.playbackLikelyToKeepUpObservation = observe(\.player.currentItem!.isPlaybackLikelyToKeepUp) { (object, change) in
//
//            object.likelyToKeepUpLabel.text = object.player.currentItem?.isPlaybackLikelyToKeepUp.description ?? "-"
//            print("playbackLikelyToKeepUpObservation-")
//        }
        
//        self.playbackLikelyToKeepUpObservation = observe(\.playerItem.isPlaybackLikelyToKeepUp) { (object, change) in
//
//            object.likelyToKeepUpLabel.text = object.player.currentItem?.isPlaybackLikelyToKeepUp.description ?? "-"
//            print("playbackLikelyToKeepUpObservation-")
//        }
        
        self.loadedTimeRangesObservation = observe(\.playerItem.loadedTimeRanges) { (object, change) in
            
            object.loadedTimeRangesLabel.text = object.player.currentItem?.loadedTimeRanges.asTimeRanges.description ?? "-"
            print("loadedTimeRangesObservation-")
        }
        
        self.playbackBufferFullObservation = observe(\.playerItem.isPlaybackBufferFull) { (object, change) in
            
            object.playbackBufferFullLabel.text = object.player.currentItem?.isPlaybackBufferFull.description ?? "-"
            print("playbackBufferFullObservation-")
        }
        self.playbackBufferEmptyObservation = observe(\.playerItem.isPlaybackBufferEmpty) { (object, change) in
            
            object.playbackBufferEmptyLabel.text = object.player.currentItem?.isPlaybackBufferEmpty.description ?? "-"
            print("playbackBufferEmptyObservation-")
        }
    }
    
    // MARK: Helpers
    
    /// Helper function to get a background color for the timeControlStatus label.
    private func labelBackgroundColor(forTimeControlStatus status: AVPlayerTimeControlStatus) -> UIColor {
        switch status {
        case .paused:
            return #colorLiteral(red: 0.8196078538894653, green: 0.2627451121807098, blue: 0.2823528945446014, alpha: 1)
            
        case .playing:
            return #colorLiteral(red: 0.2881325483322144, green: 0.6088829636573792, blue: 0.261575847864151, alpha: 1)
            
        case .waitingToPlayAtSpecifiedRate:
            return #colorLiteral(red: 0.8679746985435486, green: 0.4876297116279602, blue: 0.2578189671039581, alpha: 1)
        }
    }
    
    
    /// Helper function to get an abbreviated description for the waiting reason.
    private func abbreviatedDescription(forReasonForWaitingToPlay reason: AVPlayer.WaitingReason) -> String {
        switch reason {
        case .toMinimizeStalls:
            return "Minimizing Stalls"
            
        case .evaluatingBufferingRate:
            return "Evaluating Buffering Rate"
            
        case .noItemToPlay:
            return "No Item"
            
        default:
            return "UNKOWN"
        }
    }
    
    private func updateNonObservableProperties() {
        currentTimeLabel.text = player.currentItem?.currentTime().description ?? "-"
        timebaseRateLabel.text = player.currentItem?.timebase != nil ? CMTimebaseGetRate(player.currentItem!.timebase!).description : "-"
    }
    
    private var observerContext = 0
    
    //Update the UI as AVPlayer properties change.
    override func observeValue(forKeyPath keyPath: String?,
                      of object: Any?,
                      change: [NSKeyValueChangeKey : Any]?,
                      context: UnsafeMutableRawPointer?) {
//        guard context == &observerContext else {
//            super.observeValue(forKeyPath: keyPath, of: object, change: change, context: context)
//            return
//        }
        
        if keyPath == #keyPath(PlaybackDetailsViewController.player.currentItem.playbackLikelyToKeepUp) {
            likelyToKeepUpLabel.text = player.currentItem?.isPlaybackLikelyToKeepUp.description ?? "-"
            print("playbackLikelyToKeepUpObservation-:\(likelyToKeepUpLabel.text!)")
        }
    }
    
}

// MARK: - Extensions to improve readability of printed properties

// Add description for AVPlayerTimeControlStatus.
extension AVPlayerTimeControlStatus : CustomStringConvertible{
    public var description: String {
        switch self {
        case .paused:
            return " Paused "
            
        case .playing:
            return " Playing "
            
        case .waitingToPlayAtSpecifiedRate:
            return " Waiting "
        }
    }
}

// Simple description of CMTime, e.g., 2.4s.
extension CMTime : CustomStringConvertible {
    public var description : String {
        return String(format: "%.1fs", self.seconds)
    }
}

// Simple description of CMTimeRange, e.g., [2.4s, 2.8s].
extension CMTimeRange : CustomStringConvertible {
    public var description: String {
        return "[\(self.start), \(self.end)]"
    }
}

// Convert a collection of NSValues into an array of CMTimeRanges.
private extension Collection where Iterator.Element == NSValue {
    var asTimeRanges : [CMTimeRange] {
        return self.map({ value -> CMTimeRange in
            return value.timeRangeValue
        })
    }
}
