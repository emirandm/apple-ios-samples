/*
    Copyright (C) 2016 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information
    
    Abstract:
    View controller class to handle video playback.
*/

import UIKit
import AVFoundation

/// View controller that manages the video view and the playback controls for a given AVPlayer.
@objcMembers class PlaybackViewController: UIViewController {
    
    // MARK: Properties
    @IBOutlet weak var playerView: PlayerView!
    @IBOutlet weak var waitingIndicatorView: UIView!
    @IBOutlet weak var pauseButton: UIButton!
    @IBOutlet weak var playButton: UIButton!
    @IBOutlet weak var playImmediatelyButton: UIButton!
    @IBOutlet weak var automaticWaitingSwitch: UISwitch!
    
    private var observerContext = 0
    
    dynamic var player : AVPlayer = AVPlayer() {
        didSet {
            playerView?.player = player
            
            // Make sure the players automaticallyWaitsToMinimizeStalling follows the switch in the UI.
            if  isViewLoaded {
                automaticWaitingSwitch.isOn = player.automaticallyWaitsToMinimizeStalling
            }
        }
    }
    // MARK: KVO
    var reasonForWaitingToPlayObservation: NSKeyValueObservation?
    
    // MARK: UIViewController
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Load value for the automatic waiting switch from user defaults.
        automaticWaitingSwitch.isOn = !UserDefaults.standard.bool(forKey: "disableAutomaticWaiting")
        player.automaticallyWaitsToMinimizeStalling = automaticWaitingSwitch.isOn
        playerView?.player = player
        
        self.reasonForWaitingToPlayObservation = observe(\.player.reasonForWaitingToPlay) { (object, change) in
            // Hide the indicator view if we are not waiting to minimize stalls.
            object.waitingIndicatorView.isHidden = (object.player.reasonForWaitingToPlay != AVPlayer.WaitingReason.toMinimizeStalls)
            print("PlaybackViewController/reasonForWaitingToPlayObservation")
        }
    }
    
    // MARK: User Actions
    
    @IBAction func toggleAutomaticWaiting(_ sender: UISwitch) {
        // Check for the new value of the switch and update AVPlayer property and user defaults
        player.automaticallyWaitsToMinimizeStalling = automaticWaitingSwitch.isOn
        UserDefaults.standard.set(!automaticWaitingSwitch.isOn, forKey: "disableAutomaticWaiting")
    }
    
    @IBAction func pause(_ sender: AnyObject?) {
        player.pause()
    }
    
    @IBAction func play(_ sender: AnyObject?) {
        player.play()
    }
    
    @IBAction func playImmediately(_ sender: AnyObject?) {
        player.playImmediately(atRate: 1.0)
    }
}


